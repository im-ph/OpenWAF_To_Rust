//! 挑战令牌加密核心（对齐 Go internal/waf/challenge/token.go）。
//! HMAC-SHA256 令牌 + AES-256-GCM 通行值签验。HTML/Cookie 字符串/Hertz 部分归 P5/P7。

use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// 反重放 nonce cookie 名（对齐 Go NonceKey）。
pub const NONCE_KEY: &str = "__waf_nonce";
/// 通行 cookie 名（对齐 Go ChallengePassCookieName）。
pub const CHALLENGE_PASS_COOKIE_NAME: &str = "__waf_passed";

/// 挑战签名密钥：启动时随机 32 字节，可被 set_challenge_secret(≥16B) 覆盖。
static CHALLENGE_SECRET: LazyLock<ArcSwap<Vec<u8>>> = LazyLock::new(|| {
    let mut b = vec![0u8; 32];
    OsRng.fill_bytes(&mut b);
    ArcSwap::from_pointee(b)
});

/// 覆盖挑战密钥（对齐 Go SetChallengeSecret）：长度 ≥16 才生效。
pub fn set_challenge_secret(secret: &[u8]) {
    if secret.len() >= 16 {
        CHALLENGE_SECRET.store(Arc::new(secret.to_vec()));
    }
}

fn hmac_hex(msg: &str) -> Option<String> {
    let secret = CHALLENGE_SECRET.load();
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_slice()).ok()?;
    mac.update(msg.as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// 生成挑战令牌对（对齐 Go GenerateChallengeTokenPair）：ts + hex(HMAC(secret, reqID:ts))。
pub fn generate_challenge_token_pair(req_id: &str, now_unix: i64) -> (String, String) {
    let ts = now_unix.to_string();
    let token = hmac_hex(&format!("{req_id}:{ts}")).unwrap_or_default();
    (ts, token)
}

/// 校验挑战令牌（对齐 Go VerifyChallengeToken）：常数时间比对 + 时效校验。
pub fn verify_challenge_token(
    req_id: &str,
    ts: &str,
    token: &str,
    now_unix: i64,
    max_age_secs: i64,
) -> bool {
    let secret = CHALLENGE_SECRET.load();
    let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(secret.as_slice()) else {
        return false;
    };
    mac.update(format!("{req_id}:{ts}").as_bytes());
    let Ok(token_bytes) = hex::decode(token) else {
        return false;
    };
    if mac.verify_slice(&token_bytes).is_err() {
        return false;
    }
    let Ok(ts_int) = ts.parse::<i64>() else {
        return false;
    };
    now_unix - ts_int < max_age_secs
}

fn challenge_derive_aes_key() -> [u8; 32] {
    let secret = CHALLENGE_SECRET.load();
    let mut hasher = Sha256::new();
    hasher.update(b"owaf-challenge-aes256:");
    hasher.update(secret.as_slice());
    hasher.finalize().into()
}

fn challenge_encrypt(plaintext: &[u8]) -> Option<Vec<u8>> {
    let key_bytes = challenge_derive_aes_key();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext).ok()?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Some(out)
}

fn challenge_decrypt(ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 13 {
        return None;
    }
    let key_bytes = challenge_derive_aes_key();
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).ok()
}

fn challenge_ip_string(ip: Option<IpAddr>) -> String {
    ip.map(|i| i.to_string()).unwrap_or_default()
}

/// 签发通行值（对齐 Go SignChallengePassValue）：v2|host|ip|expiry|nonce|shield，AES-GCM + base64url。
pub fn sign_challenge_pass_value(
    host: &str,
    ip: Option<IpAddr>,
    now_unix: i64,
    ttl_secs: i64,
) -> String {
    let ttl = if ttl_secs <= 0 { 3600 } else { ttl_secs };
    let expires = now_unix + ttl;
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let payload = format!(
        "v2|{}|{}|{}|{}|shield",
        host.to_lowercase(),
        challenge_ip_string(ip),
        expires,
        hex::encode(nonce)
    );
    match challenge_encrypt(payload.as_bytes()) {
        Some(enc) => URL_SAFE_NO_PAD.encode(enc),
        None => String::new(),
    }
}

/// 校验通行值（对齐 Go VerifyChallengePassValue）：解密后校验 v2(6段)/v1(3段) 的 host/ip/expiry。
pub fn verify_challenge_pass_value(
    value: &str,
    host: &str,
    ip: Option<IpAddr>,
    now_unix: i64,
) -> bool {
    let Ok(raw) = URL_SAFE_NO_PAD.decode(value) else {
        return false;
    };
    if raw.is_empty() {
        return false;
    }
    let Some(plain) = challenge_decrypt(&raw) else {
        return false;
    };
    let plain = String::from_utf8_lossy(&plain);
    let parts: Vec<&str> = plain.split('|').collect();
    let host_l = host.to_lowercase();
    let ip_s = challenge_ip_string(ip);
    if parts.len() >= 6 && parts[0] == "v2" {
        let Ok(expires) = parts[3].parse::<i64>() else {
            return false;
        };
        return now_unix <= expires && parts[1] == host_l && parts[2] == ip_s;
    }
    if parts.len() == 3 {
        let Ok(expires) = parts[2].parse::<i64>() else {
            return false;
        };
        return now_unix <= expires && parts[0] == host_l && parts[1] == ip_s;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip() -> Option<IpAddr> {
        Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
    }

    #[test]
    fn token_pair_verifies() {
        let (ts, token) = generate_challenge_token_pair("req-1", 1000);
        assert!(verify_challenge_token("req-1", &ts, &token, 1010, 60));
    }

    #[test]
    fn token_rejects_tamper_and_expiry() {
        let (ts, token) = generate_challenge_token_pair("req-1", 1000);
        assert!(!verify_challenge_token("req-1", &ts, "deadbeef", 1010, 60));
        assert!(!verify_challenge_token("req-1", &ts, &token, 2000, 60));
        assert!(!verify_challenge_token("other", &ts, &token, 1010, 60));
    }

    #[test]
    fn pass_value_roundtrip() {
        let v = sign_challenge_pass_value("Example.COM", ip(), 1000, 3600);
        assert!(verify_challenge_pass_value(&v, "example.com", ip(), 1500));
    }

    #[test]
    fn pass_value_rejects_wrong_host_ip_expiry() {
        let v = sign_challenge_pass_value("example.com", ip(), 1000, 3600);
        assert!(!verify_challenge_pass_value(&v, "evil.com", ip(), 1500));
        let other = Some(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
        assert!(!verify_challenge_pass_value(&v, "example.com", other, 1500));
        assert!(!verify_challenge_pass_value(
            &v,
            "example.com",
            ip(),
            9_999_999
        ));
    }
}
