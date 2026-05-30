# 环境变量

下列变量对齐 Go 版 My-OpenWaf 的引导配置，将在 **P8（owaf-bin 装配）** 后于 Rust 端生效。当前库 crate 阶段尚未消费这些变量，此处先行登记为运行时契约。

| 变量 | 默认值 | 用途 |
|------|--------|------|
| `MY_OPENWAF_DB_DRIVER` | `postgres` | 数据库驱动（Rust 版仅支持 `postgres`，Go 版的 sqlite/mysql 已弃用） |
| `MY_OPENWAF_DSN` | （无） | PostgreSQL 连接串，例：`postgres://user:pass@127.0.0.1:5432/owaf` |
| `MY_OPENWAF_REDIS_ADDR` | （无） | 可选 Redis 地址，用于分布式缓存与限流 |
| `MY_OPENWAF_ADMIN_BIND` | `:9443` | 管理面监听地址（P6） |
| `MY_OPENWAF_JWT_SECRET` | （自动生成） | JWT 签名密钥；未设置时自动生成并持久化到 DB（P6） |

> 注意：`MY_OPENWAF_DSN` 含数据库口令，属机密，禁止提交到版本库；生产环境经密钥管理或环境注入提供。
