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

use sqlx::postgres::PgPool;

/// 仓库聚合器（对齐 Go repository.New(db) -> *Repos）：所有仓库共用一个连接池。
pub struct Repos {
    pub system: SystemRepo,
    pub certificate: CertificateRepo,
    pub policy: PolicyRepo,
    pub rule: RuleRepo,
    pub site: SiteRepo,
    pub site_listener: SiteListenerRepo,
    pub admin_account: AdminAccountRepo,
    pub admin_api_key: AdminApiKeyRepo,
    pub refresh_token: RefreshTokenRepo,
    pub security_event: SecurityEventRepo,
    pub access_log: AccessLogRepo,
    pub drop_event: DropEventRepo,
    pub bot_score: BotScoreRepo,
    pub ip_list: IpListRepo,
    pub cve_rule: CveRuleRepo,
    pub cve_sync_log: CveSyncLogRepo,
    pub fingerprint: FingerprintRepo,
}

impl Repos {
    pub fn new(pool: PgPool) -> Self {
        Self {
            system: SystemRepo::new(pool.clone()),
            certificate: CertificateRepo::new(pool.clone()),
            policy: PolicyRepo::new(pool.clone()),
            rule: RuleRepo::new(pool.clone()),
            site: SiteRepo::new(pool.clone()),
            site_listener: SiteListenerRepo::new(pool.clone()),
            admin_account: AdminAccountRepo::new(pool.clone()),
            admin_api_key: AdminApiKeyRepo::new(pool.clone()),
            refresh_token: RefreshTokenRepo::new(pool.clone()),
            security_event: SecurityEventRepo::new(pool.clone()),
            access_log: AccessLogRepo::new(pool.clone()),
            drop_event: DropEventRepo::new(pool.clone()),
            bot_score: BotScoreRepo::new(pool.clone()),
            ip_list: IpListRepo::new(pool.clone()),
            cve_rule: CveRuleRepo::new(pool.clone()),
            cve_sync_log: CveSyncLogRepo::new(pool.clone()),
            fingerprint: FingerprintRepo::new(pool),
        }
    }
}
