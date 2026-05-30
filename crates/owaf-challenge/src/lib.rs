//! owaf-challenge：挑战系统加密核心（HMAC 令牌 + AES-256-GCM 通行值 + PoW 验证）。
//! 移植 Go internal/waf/challenge 的框架无关部分；HTML/Cookie/Redis/WASM 归后续阶段。

pub mod pow;
pub mod token;
