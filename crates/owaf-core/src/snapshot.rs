use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;

/// 路由解析后的站点运行时（P1 仅含路由必需字段，后续阶段按需扩展）。
#[derive(Debug, Clone, Default)]
pub struct SiteRuntime {
    pub bind: String,
    pub upstream_urls: Vec<String>,
}

/// 数据面只读快照（通过 ArcSwap 原子换页热更新）。
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub revision: u64,
    pub sites: HashMap<String, SiteRuntime>,
    pub default_block_html: String,
}

/// 站点映射键：bind + '\0' + 归一化 host。
pub fn site_map_key(bind: &str, host: &str) -> String {
    format!("{bind}\0{}", host.trim().to_lowercase())
}

/// 归一化 host：小写、去空白、剥离末尾纯数字端口。
pub fn normalize_match_host(host: &str) -> String {
    let host = host.trim().to_lowercase();
    if let Some(i) = host.rfind(':') {
        let port = &host[i + 1..];
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return host[..i].to_string();
        }
    }
    host
}

fn is_ip_address(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}

impl Snapshot {
    /// 匹配站点：精确 → 通配（非 IP 且含点）→ 无。
    pub fn match_site(&self, bind: &str, host_header: &str) -> Option<&SiteRuntime> {
        let host = normalize_match_host(host_header);
        if host.is_empty() {
            return None;
        }
        if let Some(rt) = self.sites.get(&site_map_key(bind, &host)) {
            return Some(rt);
        }
        if is_ip_address(&host) {
            return None;
        }
        let idx = host.find('.')?;
        if idx == 0 {
            return None;
        }
        let wild = format!("*.{}", &host[idx + 1..]);
        self.sites.get(&site_map_key(bind, &wild))
    }
}

/// 原子快照持有器：无锁读 + 原子换页（对齐 Go `atomic.Pointer[Snapshot]`）。
pub struct Holder(ArcSwap<Snapshot>);

impl Holder {
    pub fn new(s: Snapshot) -> Self {
        Self(ArcSwap::from_pointee(s))
    }
    pub fn load(&self) -> Arc<Snapshot> {
        self.0.load_full()
    }
    pub fn store(&self, s: Snapshot) {
        self.0.store(Arc::new(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_numeric_port_only() {
        assert_eq!(normalize_match_host("  Example.COM:8080 "), "example.com");
        assert_eq!(normalize_match_host("example.com"), "example.com");
        // 非数字端口不剥离（避免误伤 IPv6 等场景）。
        assert_eq!(normalize_match_host("host:abc"), "host:abc");
    }

    #[test]
    fn match_site_exact_then_wildcard() {
        let mut sites = HashMap::new();
        sites.insert(site_map_key(":80", "*.example.com"), SiteRuntime::default());
        let sn = Snapshot {
            revision: 1,
            sites,
            default_block_html: String::new(),
        };
        assert!(sn.match_site(":80", "api.example.com:80").is_some());
        assert!(sn.match_site(":80", "other.org").is_none());
    }
}
