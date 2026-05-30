//! owaf-store 错误类型（对齐 Go store 层的 error 返回）。

use thiserror::Error;

/// 存储层统一错误。
#[derive(Debug, Error)]
pub enum StoreError {
    /// 数据库错误（sqlx/PostgreSQL）。
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// Redis 缓存错误。
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),
    /// 口令/令牌 bcrypt 哈希错误。
    #[error("bcrypt error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
}

/// 存储层结果别名。
pub type Result<T> = std::result::Result<T, StoreError>;
