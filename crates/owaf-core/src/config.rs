use std::env;

use crate::error::{Result, WafError};

/// 进程启动配置：PostgreSQL（必填）+ 可选 Redis + admin 监听。
/// 机密/必填项缺失时 fail-fast（backend-core 规则）。
#[derive(Debug, Clone)]
pub struct Config {
    pub pg_dsn: String,
    pub redis_addr: Option<String>,
    pub redis_password: String,
    pub redis_db: i64,
    pub admin_bind: String,
    pub admin_static_dir: Option<String>,
    pub data_dir: String,
}

fn env_trim(key: &str) -> String {
    env::var(key).unwrap_or_default().trim().to_string()
}

fn env_opt(key: &str) -> Option<String> {
    let v = env_trim(key);
    if v.is_empty() { None } else { Some(v) }
}

impl Config {
    /// 从环境变量加载；PG DSN（MY_OPENWAF_DSN）缺失则返回 Config 错误。
    pub fn from_env() -> Result<Self> {
        let pg_dsn = env_trim("MY_OPENWAF_DSN");
        if pg_dsn.is_empty() {
            return Err(WafError::Config(
                "MY_OPENWAF_DSN (PostgreSQL DSN) is required".into(),
            ));
        }

        let data_dir = env_opt("MY_OPENWAF_DATA").unwrap_or_else(|| "./data".into());
        let admin_bind = env_opt("MY_OPENWAF_ADMIN_BIND").unwrap_or_else(|| ":9443".into());
        let redis_db = env_trim("MY_OPENWAF_REDIS_DB").parse::<i64>().unwrap_or(0);

        Ok(Self {
            pg_dsn,
            redis_addr: env_opt("MY_OPENWAF_REDIS_ADDR"),
            redis_password: env_trim("MY_OPENWAF_REDIS_PASSWORD"),
            redis_db,
            admin_bind,
            admin_static_dir: env_opt("MY_OPENWAF_ADMIN_STATIC_DIR"),
            data_dir,
        })
    }
}
