//! owaf-core：WAF 共享内核（错误类型、配置与快照基础类型）。
//! 所有上层 crate（detect / dataplane / admin / store）依赖本 crate。

pub mod config;
pub mod error;
pub mod snapshot;

pub use config::Config;
pub use error::{Result, WafError};
pub use snapshot::{Holder, SiteRuntime, Snapshot};
