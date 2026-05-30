//! 输入归一化层：忠实移植 Go internal/waf/owasp 的 normalize / normalizeWithDecode
//! 及其解码辅助。细节保真（与 Go stdlib 逐字对齐）留待后续优化 pass。
#![allow(clippy::collapsible_if)]

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use regex::Regex;

const MAX_TOKENS_PER_LEVEL: usize = 128;
const MAX_TOTAL_BYTES: usize = 32768;
const MAX_DEPTH: u32 = 3;

/// 非 panic 编译：失败则丢弃该模式（静态模式不会失败，仅为遵守零 unwrap/expect）。
fn compile(patterns: &[(&'static str, &'static str)]) -> Vec<(Regex, &'static str)> {
    patterns
        .iter()
        .filter_map(|(p, r)| Regex::new(p).ok().map(|re| (re, *r)))
        .collect()
}

static OVERLONG: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    compile(&[
        (r"(?i)%c0%ae", "."),
        (r"(?i)%c0%af", "/"),
        (r"(?i)%c1%9c", "\\"),
        (
            r"(?i)(%c0%bc|%e0%80%bc|%f0%80%80%bc|%f8%80%80%80%bc|%fc%80%80%80%80%bc)",
            "<",
        ),
        (r"(?i)(%c0%be|%e0%80%be|%f0%80%80%be)", ">"),
    ])
});

static RE_UTF7: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"\+([A-Za-z0-9+/]{2,8})-?").ok());

fn is_base64_alphanum(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn is_base64_char(b: u8) -> bool {
    is_base64_alphanum(b) || b == b'+' || b == b'/'
}

/// 快速预筛：是否含可能需要解码的字符（对齐 Go needsDecoding）。
pub fn needs_decoding(s: &str) -> bool {
    let b = s.as_bytes();
    for (i, &c) in b.iter().enumerate() {
        match c {
            b'%' | b'\\' | b'&' => return true,
            b'+' if i + 2 < b.len() && b[i + 1] == b'A' => return true,
            _ => {}
        }
    }
    false
}

/// 是否含 8+ 连续 base64 字符（对齐 Go hasBase64Candidate）。
pub fn has_base64_candidate(s: &str) -> bool {
    let mut run = 0;
    for &c in s.as_bytes() {
        if is_base64_char(c) {
            run += 1;
            if run >= 8 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// 提取 base64 token（[A-Za-z0-9+/]{8,}={0,2}，至多 max 个）。
fn find_base64_tokens(s: &str, max: usize) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < max {
        if is_base64_char(b[i]) {
            let start = i;
            while i < b.len() && is_base64_char(b[i]) {
                i += 1;
            }
            let mut end = i;
            let mut pad = 0;
            while end < b.len() && b[end] == b'=' && pad < 2 {
                end += 1;
                pad += 1;
            }
            if end - start >= 8 {
                out.push(&s[start..end]);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    if let Ok(d) = STANDARD.decode(s) {
        return Some(d);
    }
    if let Ok(d) = STANDARD_NO_PAD.decode(s) {
        return Some(d);
    }
    let mapped: String = s
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    STANDARD_NO_PAD.decode(mapped).ok()
}

/// 解码可疑 base64 token（对齐 Go decodeBase64IfSuspicious：可打印率门限 + 剥离前导非字母数字重试）。
pub fn decode_base64_if_suspicious(s: &str) -> String {
    let mut cur = s;
    loop {
        if cur.len() < 8 {
            return String::new();
        }
        let Some(decoded) = base64_decode(cur) else {
            return String::new();
        };
        if decoded.is_empty() {
            return String::new();
        }
        let printable = decoded
            .iter()
            .filter(|&&b| (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r')
            .count();
        let ratio = printable as f64 / decoded.len() as f64;
        let min_ratio = if cur.len() >= 20 { 0.50 } else { 0.70 };
        if ratio < min_ratio {
            let bytes = cur.as_bytes();
            if cur.len() > 8 && !is_base64_alphanum(bytes[0]) {
                cur = &cur[1..];
                continue;
            }
            return String::new();
        }
        return String::from_utf8_lossy(&decoded).into_owned();
    }
}

/// 解码 \xNN 十六进制转义（对齐 Go decodeHexEscapes）。
pub fn decode_hex_escapes(s: &str) -> String {
    if !s.contains("\\x") {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len() + 1
            && i + 1 < b.len()
            && b[i + 1] == b'x'
            && i + 3 < b.len() + 1
        {
            if i + 4 <= b.len() {
                let h = &s[i + 2..i + 4];
                if let Ok(v) = u8::from_str_radix(h, 16) {
                    out.push(v);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 手写 query unescape，对齐 Go url.QueryUnescape：%XX→字节，'+'→空格，非法 %XX 返回 None。
pub(crate) fn query_unescape(s: &str) -> Option<String> {
    url_unescape(s, true)
}

/// 手写 path unescape，对齐 Go url.PathUnescape：%XX→字节，'+' 保留，非法 %XX 返回 None。
fn path_unescape(s: &str) -> Option<String> {
    url_unescape(s, false)
}

fn url_unescape(s: &str, plus_to_space: bool) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                if i + 2 >= b.len() {
                    return None;
                }
                let h = &s[i + 1..i + 3];
                let v = u8::from_str_radix(h, 16).ok()?;
                out.push(v);
                i += 3;
            }
            b'+' if plus_to_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// 聚焦 HTML 实体解码：数字实体 &#NN; / &#xNN; + 常见命名实体（全表保真留待后续）。
fn html_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'&' {
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        let Some(semi_rel) = s[i..].find(';') else {
            out.push('&');
            i += 1;
            continue;
        };
        let semi = i + semi_rel;
        if semi - i > 12 {
            out.push('&');
            i += 1;
            continue;
        }
        let entity = &s[i + 1..semi];
        let decoded = decode_entity(entity);
        match decoded {
            Some(ch) => {
                out.push(ch);
                i = semi + 1;
            }
            None => {
                out.push('&');
                i += 1;
            }
        }
    }
    out
}

fn decode_entity(entity: &str) -> Option<char> {
    if let Some(num) = entity.strip_prefix('#') {
        let code = if let Some(hex) = num.strip_prefix('x').or_else(|| num.strip_prefix('X')) {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            num.parse::<u32>().ok()?
        };
        return char::from_u32(code);
    }
    match entity {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        "nbsp" => Some(' '),
        _ => None,
    }
}

/// JS 转义解码：\xNN、\uXXXX、\u{XXXX}、八进制 \NNN（对齐 Go decodeJSEscapes）。
pub fn decode_js_escapes(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' || i + 1 >= b.len() {
            out.push(b[i]);
            i += 1;
            continue;
        }
        match b[i + 1] {
            b'x' | b'X' => {
                if i + 4 <= b.len()
                    && let Ok(v) = u8::from_str_radix(&s[i + 2..i + 4], 16)
                {
                    out.push(v);
                    i += 4;
                    continue;
                }
            }
            b'u' | b'U' => {
                if i + 2 < b.len() && b[i + 2] == b'{' {
                    if let Some(end_rel) = s[i + 3..].find('}') {
                        if end_rel > 0 && end_rel <= 6 {
                            if let Ok(v) = u32::from_str_radix(&s[i + 3..i + 3 + end_rel], 16) {
                                if let Some(ch) = char::from_u32(v) {
                                    let mut buf = [0u8; 4];
                                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                                    i = i + 3 + end_rel + 1;
                                    continue;
                                }
                            }
                        }
                    }
                } else if i + 6 <= b.len()
                    && let Ok(v) = u32::from_str_radix(&s[i + 2..i + 6], 16)
                    && let Some(ch) = char::from_u32(v)
                {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    i += 6;
                    continue;
                }
            }
            c if c.is_ascii_digit() && c <= b'7' => {
                let mut end = i + 2;
                while end < b.len() && end < i + 4 && b[end] >= b'0' && b[end] <= b'7' {
                    end += 1;
                }
                if let Ok(v) = u8::from_str_radix(&s[i + 1..end], 8) {
                    out.push(v);
                    i = end;
                    continue;
                }
            }
            _ => {}
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// UTF-7 序列解码：+ADw- → < 等（对齐 Go decodeUTF7Sequences，UTF-16BE）。
pub fn decode_utf7_sequences(s: &str) -> String {
    let Some(re) = &*RE_UTF7 else {
        return s.to_string();
    };
    re.replace_all(s, |caps: &regex::Captures| {
        let m = &caps[0];
        let mut encoded = m.trim_start_matches('+').trim_end_matches('-').to_string();
        while !encoded.len().is_multiple_of(4) {
            encoded.push('=');
        }
        let Ok(decoded) = STANDARD.decode(&encoded) else {
            return m.to_string();
        };
        if decoded.is_empty() {
            return m.to_string();
        }
        let mut out = String::new();
        let mut i = 0;
        while i + 1 < decoded.len() {
            let r = (decoded[i] as u32) << 8 | decoded[i + 1] as u32;
            if r > 0 && r < 0xFFFF {
                if let Some(ch) = char::from_u32(r) {
                    out.push(ch);
                }
            }
            i += 2;
        }
        if out.is_empty() { m.to_string() } else { out }
    })
    .into_owned()
}

/// 折叠连续空白为单个空格（对齐 Go collapseWhitespace）。
pub fn collapse_whitespace(s: &str) -> String {
    let b = s.as_bytes();
    let needs = b.iter().enumerate().any(|(i, &c)| {
        matches!(c, b'\t' | b'\n' | b'\r' | 0x0c | 0x0b)
            || (c == b' ' && i + 1 < b.len() && matches!(b[i + 1], b' ' | b'\t' | b'\n' | b'\r'))
    });
    if !needs {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut in_space = false;
    for &c in b {
        if matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b) {
            if !in_space {
                out.push(' ');
                in_space = true;
            }
        } else {
            out.push(c as char);
            in_space = false;
        }
    }
    out
}

/// 剥离内联 SQL/C 注释（保留 /*! ... */ 版本化注释，对齐 Go stripSQLComments）。
pub fn strip_sql_comments(s: &str) -> String {
    let has_block = s.contains("/*");
    let has_line = s.contains('#') || s.contains("--");
    if !has_block && !has_line {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if i + 1 < b.len() && b[i] == b'/' && b[i + 1] == b'*' {
            if i + 2 < b.len() && b[i + 2] == b'!' {
                out.push(b[i]);
                i += 1;
                continue;
            }
            match s[i + 2..].find("*/") {
                Some(end) => i = i + 2 + end + 2,
                None => {
                    out.push(b[i]);
                    i += 1;
                }
            }
        } else if is_line_comment_start(b, i) {
            match s[i..].find(['\r', '\n']) {
                Some(end) => i += end,
                None => break,
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_line_comment_start(b: &[u8], i: usize) -> bool {
    if b[i] == b'#' {
        let prev_ok = i == 0 || !matches!(b[i - 1], b'=' | b'/' | b'?' | b'&' | b'"' | b'\'');
        let next_ok = i + 1 >= b.len() || matches!(b[i + 1], b' ' | b'\t' | b'\n' | b'\r');
        return prev_ok && next_ok;
    }
    if i + 1 < b.len() && b[i] == b'-' && b[i + 1] == b'-' {
        return i + 2 >= b.len() || matches!(b[i + 2], b' ' | b'\t' | b'\n' | b'\r');
    }
    false
}

/// 归一化主流水线（对齐 Go normalize 的 10 步顺序）。
pub fn normalize(input: &str) -> String {
    let mut s = input.to_string();
    if s.contains('%') {
        for (re, rep) in OVERLONG.iter() {
            s = re.replace_all(&s, *rep).into_owned();
        }
    }
    // 多轮 URL 解码：首轮 query（'+'→空格），后续 path（仅 %XX）。
    for i in 0..3 {
        let decoded = if i == 0 {
            query_unescape(&s)
        } else {
            path_unescape(&s)
        };
        match decoded {
            Some(d) if d != s => s = d,
            _ => break,
        }
    }
    // 多轮 HTML 实体解码。
    for _ in 0..2 {
        let d = html_unescape(&s);
        if d == s {
            break;
        }
        s = d;
    }
    if s.contains('\\') {
        s = decode_js_escapes(&s);
    }
    // JS 解码后可能产生百分号编码，再多轮 path 解码。
    for _ in 0..3 {
        if !s.contains('%') {
            break;
        }
        match path_unescape(&s) {
            Some(d) if d != s => s = d,
            _ => break,
        }
    }
    if s.contains("+A") {
        s = decode_utf7_sequences(&s);
    }
    s = s.to_lowercase();
    s = s.replace('\u{0}', " ");
    s = strip_sql_comments(&s);
    collapse_whitespace(&s)
}

/// 归一化 + base64 透明递归解码（对齐 Go normalizeWithDecode）。
pub fn normalize_with_decode(raw: &str) -> String {
    let mut raw = raw.to_string();
    if needs_decoding(&raw) && raw.contains("\\x") {
        let hex_decoded = decode_hex_escapes(&raw);
        if hex_decoded != raw {
            raw = hex_decoded;
        }
    }

    let s = normalize(&raw);
    if s.len() < 8 || (!has_base64_candidate(&s) && !has_base64_candidate(&raw)) {
        return s;
    }

    // 保留大小写的 URL 解码版本，供 base64 提取（normalize 会小写破坏 base64 大小写）。
    let mut url_decoded = raw.clone();
    for i in 0..3 {
        let d = if i == 0 {
            query_unescape(&url_decoded)
        } else {
            path_unescape(&url_decoded)
        };
        match d {
            Some(v) if v != url_decoded => url_decoded = v,
            _ => break,
        }
    }
    let mut sources: Vec<String> = vec![raw.clone(), s.clone()];
    if url_decoded != raw {
        sources.push(url_decoded.clone());
    }
    if url_decoded.contains('\\') {
        let js = decode_js_escapes(&url_decoded);
        if js != url_decoded {
            sources.push(js);
        }
    }

    let mut out = String::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::with_capacity(8);
    let mut found = false;
    let mut total_bytes = 0usize;
    decode_tokens(
        &sources,
        1,
        &s,
        &mut out,
        &mut seen,
        &mut found,
        &mut total_bytes,
    );

    if found { out } else { s }
}

#[allow(clippy::too_many_arguments)]
fn decode_tokens(
    srcs: &[String],
    depth: u32,
    base: &str,
    out: &mut String,
    seen: &mut std::collections::HashSet<String>,
    found: &mut bool,
    total_bytes: &mut usize,
) {
    if depth > MAX_DEPTH || *total_bytes >= MAX_TOTAL_BYTES {
        return;
    }
    for src in srcs {
        for tok in find_base64_tokens(src, MAX_TOKENS_PER_LEVEL) {
            if seen.contains(tok) {
                continue;
            }
            seen.insert(tok.to_string());
            let decoded = decode_base64_if_suspicious(tok);
            if decoded.is_empty() {
                continue;
            }
            *total_bytes += decoded.len();
            if *total_bytes > MAX_TOTAL_BYTES {
                return;
            }
            if !*found {
                out.push_str(base);
                *found = true;
            }
            out.push(' ');
            out.push_str(&normalize(&decoded));

            let mut next: Vec<String> = vec![decoded.clone()];
            if decoded.contains('\\') {
                let js = decode_js_escapes(&decoded);
                if js != decoded {
                    let norm_js = normalize(&js);
                    out.push(' ');
                    out.push_str(&norm_js);
                    next.push(js);
                    next.push(norm_js);
                }
            }
            decode_tokens(
                next.as_slice(),
                depth + 1,
                base,
                out,
                seen,
                found,
                total_bytes,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_pass_url_decode() {
        // %2553 → %53 → 'S'（双重编码）。
        assert!(
            normalize("%2553elect").contains("select")
                || normalize("%2553elect").contains("select")
        );
    }

    #[test]
    fn strip_block_comment_joins_tokens() {
        assert_eq!(strip_sql_comments("sel/**/ect"), "select");
        // 版本化注释保留。
        assert!(strip_sql_comments("/*!50000select*/").contains("/*!"));
    }

    #[test]
    fn overlong_dot_slash_decoded() {
        let n = normalize("%c0%ae%c0%af");
        assert!(n.contains('.') && n.contains('/'));
    }

    #[test]
    fn base64_transparent_decode_exposes_payload() {
        use base64::Engine;
        let enc = base64::engine::general_purpose::STANDARD.encode("union select 1");
        let n = normalize_with_decode(&format!("q={enc}"));
        assert!(n.contains("union") && n.contains("select"));
    }

    #[test]
    fn clean_string_unchanged_fastpath() {
        assert_eq!(normalize("hello"), "hello");
    }
}
