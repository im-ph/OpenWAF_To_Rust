//! owaf-detect：OWASP/CVE 检测引擎（按子步移植 Go internal/waf/owasp,cve）。
//! 本文件为 P2 子步 1 的检测基础类型。

pub mod cve;
pub mod normalize;
pub mod owasp;
pub mod targets;

/// 内置规则集版本（对齐 Go BuiltinVersion）。
pub const BUILTIN_VERSION: &str = "builtin_owasp_v2";

/// 单个扫描目标的长度上限，限制正则执行时间（对齐 Go maxTargetLen）。
pub const MAX_TARGET_LEN: usize = 16384;

/// OWASP 攻击类别。`as_str` 返回值是配置/存储的对外契约，必须与 Go 字符串逐字一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Sqli,
    Webshell,
    RevShell,
    Xss,
    PathTraversal,
    Ssrf,
    CmdInjection,
    Xxe,
    LdapInjection,
    FileUpload,
    ProtocolViolation,
    NoSqlInjection,
    TemplateInjection,
    JndiInjection,
    CrlfInjection,
    ExpressionLanguage,
    Deserialization,
    GraphqlInjection,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Sqli => "sqli",
            Category::Webshell => "webshell",
            Category::RevShell => "revshell",
            Category::Xss => "xss",
            Category::PathTraversal => "path_traversal",
            Category::Ssrf => "ssrf",
            Category::CmdInjection => "cmd_injection",
            Category::Xxe => "xxe",
            Category::LdapInjection => "ldap_injection",
            Category::FileUpload => "file_upload",
            Category::ProtocolViolation => "protocol_violation",
            Category::NoSqlInjection => "nosql_injection",
            Category::TemplateInjection => "template_injection",
            Category::JndiInjection => "jndi_injection",
            Category::CrlfInjection => "crlf_injection",
            Category::ExpressionLanguage => "expression_language",
            Category::Deserialization => "deserialization",
            Category::GraphqlInjection => "graphql_injection",
        }
    }
}

/// 一次检测命中（对齐 Go OWASPHit）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub category: Category,
    pub rule_id: String,
    pub score: i32,
    pub desc: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_wire_strings_match_go() {
        assert_eq!(Category::Sqli.as_str(), "sqli");
        assert_eq!(Category::PathTraversal.as_str(), "path_traversal");
        assert_eq!(Category::GraphqlInjection.as_str(), "graphql_injection");
    }
}
