//! 热缓存与异步写队列抽象（对齐 Go HotCacheBackend / WriteQueueBackend）。
//! 定义为 trait 以解耦 Redis/observability，避免循环依赖；具体实现与接线归后续阶段。

use std::time::Duration;

/// Redis 热数据缓存后端（对齐 Go HotCacheBackend）。
pub trait HotCache: Send + Sync {
    fn available(&self) -> bool;
    fn get_list_raw(&self, key: &str) -> Option<(Vec<u8>, i64)>;
    fn set_list(&self, key: &str, items: &[u8], total: i64, ttl: Duration);
    fn invalidate(&self, key: &str);
    fn invalidate_pattern(&self, pattern: &str);
}

/// 异步批量写队列后端（对齐 Go WriteQueueBackend）。
pub trait WriteQueue: Send + Sync {
    /// 提交一个异步写任务（fire-and-forget）。
    fn submit(&self, sql: String, payload: Vec<u8>);
}
