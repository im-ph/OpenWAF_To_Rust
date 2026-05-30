//! 扫描目标提取层（对齐 Go collectTargets + 各 extract* 辅助）。
//! body 解析（form/JSON/multipart/二进制跳过）在数据面层完成后以 body_targets 传入，本层保持框架无关。

use crate::normalize::{has_base64_candidate, query_unescape};

/// 略过的噪声请求头（代表性集合；全表保真留待后续 parity pass）。
const SKIP_HEADERS: &[&str] = &[
    "host",
    "connection",
    "content-length",
    "accept-encoding",
    "accept-language",
    "cache-control",
];

/// 纯 hex（含 '-'）且 ≥16 字符 → 视为会话令牌（对齐 Go isLikelySessionID）。
fn is_likely_session_id(val: &str) -> bool {
    val.len() >= 16 && val.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')
}

/// 拆分 Cookie 头取各值，过滤会话令牌避免误报（对齐 Go extractCookieValues）。
fn extract_cookie_values(raw: &str) -> Vec<String> {
    raw.split(';')
        .filter_map(|pair| {
            let (_, val) = pair.trim().split_once('=')?;
            let val = val.trim();
            if val.is_empty() || is_likely_session_id(val) {
                None
            } else {
                Some(val.to_string())
            }
        })
        .collect()
}

/// 仅取 Referer 的 query 与 fragment（不含 scheme+host，避 SSRF 误报，对齐 Go extractRefererTargets）。
fn extract_referer_targets(referer: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(q) = referer.find('?') {
        match referer[q + 1..].split_once('#') {
            Some((query, frag)) => {
                if !query.is_empty() {
                    out.push(query.to_string());
                }
                if !frag.is_empty() {
                    out.push(frag.to_string());
                }
            }
            None => {
                let rest = &referer[q + 1..];
                if !rest.is_empty() {
                    out.push(rest.to_string());
                }
            }
        }
    } else if let Some(h) = referer.find('#') {
        let frag = &referer[h + 1..];
        if !frag.is_empty() {
            out.push(frag.to_string());
        }
    }
    out
}

/// query 值采样门限（对齐 Go shouldScanDecodedQueryValue：长串/多重转义/base64 候选才扫）。
fn should_scan_decoded_query_value(raw: &str, decoded: &str) -> bool {
    if decoded.is_empty() {
        return false;
    }
    if decoded.len() >= 256 {
        return true;
    }
    if decoded.matches("\\\\u00").count() >= 4 {
        return true;
    }
    (has_base64_candidate(raw) || has_base64_candidate(decoded)) && decoded.len() >= 12
}

/// 拆分 query 取各值并按采样门限过滤（对齐 Go extractQueryValues）。
fn extract_query_values(query: &str) -> Vec<String> {
    let mut out = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((_, value)) = pair.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        let decoded = query_unescape(value).unwrap_or_else(|| value.to_string());
        if should_scan_decoded_query_value(value, &decoded) {
            out.push(decoded);
        }
    }
    out
}

/// 组装扫描目标：path + query + query 值采样 + 各请求头（cookie/referer 特殊处理，skip 噪声头）。
/// headers 以 (name, value) 切片传入，保持与具体 HTTP 框架解耦。
pub fn collect_targets(path: &str, query: &str, headers: &[(String, String)]) -> Vec<String> {
    let mut out = vec![path.to_string(), query.to_string()];
    if !query.is_empty() {
        out.extend(extract_query_values(query));
    }
    for (k, v) in headers {
        let lk = k.to_lowercase();
        match lk.as_str() {
            "cookie" => out.extend(extract_cookie_values(v)),
            "referer" => out.extend(extract_referer_targets(v)),
            _ if SKIP_HEADERS.contains(&lk.as_str()) => {}
            _ => out.push(v.clone()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_session_id_filtered() {
        let vals = extract_cookie_values("sid=deadbeefdeadbeef12; note=hello");
        assert_eq!(vals, vec!["hello".to_string()]);
    }

    #[test]
    fn referer_drops_scheme_host() {
        let t = extract_referer_targets("http://10.0.0.1/p?a=1#frag");
        assert_eq!(t, vec!["a=1".to_string(), "frag".to_string()]);
    }

    #[test]
    fn collect_includes_path_query() {
        let t = collect_targets("/x", "q=1", &[]);
        assert!(t.contains(&"/x".to_string()) && t.contains(&"q=1".to_string()));
    }
}
