//! owaf-store：PostgreSQL + Redis 仓储层（移植 Go internal/store）。
//! 采用 sqlx 运行时查询，离线可编译；模型与仓库按域分批补全。

pub mod cache;
pub mod db;
pub mod error;
pub mod models;
pub mod repository;
pub mod seed;

pub use db::Db;
pub use error::{Result, StoreError};
