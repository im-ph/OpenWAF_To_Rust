//! 工作量证明核心（对齐 Go internal/waf/challenge/pow.go 的验证部分）。
//! JS 脚本生成 / WASM 资源 / gzip 归前端 P7。

use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// 生成 PoW nonce（对齐 Go GeneratePoWNonce）：hex(16 随机字节)。
pub fn generate_pow_nonce() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn sha256_hex(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

/// 校验 PoW 解（对齐 Go VerifyPoW）：hash 前 difficulty 位全 '0' 且 sha256(nonce+counter) 复算相等。
pub fn verify_pow(nonce: &str, counter: i64, hash: &str, difficulty: usize) -> bool {
    let Some(prefix) = hash.as_bytes().get(..difficulty) else {
        return false;
    };
    if !prefix.iter().all(|&b| b == b'0') {
        return false;
    }
    sha256_hex(&format!("{nonce}{counter}")) == hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pow_verifies_real_solution() {
        let nonce = "abc";
        let mut counter = 0i64;
        let hash = loop {
            let h = sha256_hex(&format!("{nonce}{counter}"));
            if h.starts_with('0') {
                break h;
            }
            counter += 1;
        };
        assert!(verify_pow(nonce, counter, &hash, 1));
        assert!(!verify_pow(nonce, counter + 1, &hash, 1));
    }

    #[test]
    fn nonce_is_32_hex_chars() {
        assert_eq!(generate_pow_nonce().len(), 32);
    }
}
