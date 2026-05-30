# owaf-rs

My-OpenWaf（Go 版 Web 应用防火墙）的 **Rust 重构**。本仓库以 Cargo Workspace 组织，按阶段（P0–P8）将 Go 实现忠实移植到 Rust。

> 状态：**移植进行中（P4/8）**。当前为库 crate 阶段，尚无可独立运行的二进制；数据面、管理面、前端与装配将在 P5–P8 落地。

## Workspace 结构

| Crate | 职责 | 对应 Go 模块 | 状态 |
|-------|------|-------------|------|
| `owaf-core` | 配置加载、不可变快照（ArcSwap 热更新）、错误层 | `internal/core`、`internal/snapshot` | ✅ |
| `owaf-detect` | OWASP 17 类检测、CVE 子系统、输入归一化管线 | `internal/waf/owasp*`、`cve*` | ✅ |
| `owaf-challenge` | HMAC 令牌、AES-256-GCM 通行值、PoW 工作量验证 | `internal/waf` 挑战部分 | ✅ |
| `owaf-store` | PostgreSQL 仓储层（sqlx 运行时查询）+ Redis 缓存契约 | `internal/store` | 🚧 P4 |
| `owaf-dataplane` | pingora 反向代理 + WAF 流水线 | `internal/dataplane` | ⏳ P5 |
| `owaf-admin` | REST API + JWT 鉴权 | `internal/admin` | ⏳ P6 |
| 前端 | Leptos 重写管理界面 | `frontend` | ⏳ P7 |
| `owaf-bin` | 装配与启动 | `cmd` | ⏳ P8 |

## 技术选型

- **持久化**：PostgreSQL（`sqlx` 0.8，运行时查询，非编译期宏 —— 离线即可编译）+ Redis 缓存。
- **HTTP 栈**：pingora（数据面，P5）。
- **前端**：Leptos（P7）。
- 生产代码遵循 IGES 规范：禁止 `.unwrap()` / `.expect()`，错误经 `thiserror` 枚举显式传播。

## 构建与验证

```bash
cargo check --workspace
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## 安全扫描

```bash
cargo audit            # 依赖漏洞扫描（RustSec 公告库）
```

已分析的不适用项记录于 [`.cargo/audit.toml`](./.cargo/audit.toml)。

## 环境变量

见 [ENV_VARS.md](./ENV_VARS.md)（P8 装配后生效）。
