use std::result::Result as StdResult;

/// 全局错误类型，覆盖 WAF 各子系统的错误语义。
#[derive(Debug, thiserror::Error)]
pub enum WafError {
    #[error("config error: {0}")]
    Config(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("redis error: {0}")]
    Redis(String),

    #[error("upstream proxy error: {0}")]
    Upstream(String),

    #[error("detection engine error: {0}")]
    Detect(String),

    #[error("challenge error: {0}")]
    Challenge(String),

    #[error("auth error: {0}")]
    Auth(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// 统一 Result 别名。
pub type Result<T> = StdResult<T, WafError>;
