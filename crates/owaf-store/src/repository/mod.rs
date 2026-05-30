//! 仓库层（对齐 Go internal/store/repository）。
//! 已落地：system / certificate / policy / rule / site / site_listener / auth / events；cve 等后续补全。

pub mod access_log;
pub mod admin_account;
pub mod admin_api_key;
pub mod bot_score;
pub mod certificate;
pub mod cve_rule;
pub mod drop_event;
pub mod fingerprint;
pub mod ip_list;
pub mod policy;
pub mod refresh_token;
pub mod rule;
pub mod security_event;
pub mod site;
pub mod site_listener;
pub mod system;

pub use access_log::AccessLogRepo;
pub use admin_account::AdminAccountRepo;
pub use admin_api_key::AdminApiKeyRepo;
pub use bot_score::BotScoreRepo;
pub use certificate::CertificateRepo;
pub use cve_rule::{CveRuleRepo, CveSyncLogRepo};
pub use drop_event::DropEventRepo;
pub use fingerprint::FingerprintRepo;
pub use ip_list::IpListRepo;
pub use policy::PolicyRepo;
pub use refresh_token::RefreshTokenRepo;
pub use rule::RuleRepo;
pub use security_event::SecurityEventRepo;
pub use site::SiteRepo;
pub use site_listener::SiteListenerRepo;
pub use system::SystemRepo;
