//! 默认数据种子（对齐 Go store.SeedDefaults / SeedDataplaneDefaults）。

use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::repository::AdminApiKeyRepo;

/// 生成 n 字节随机十六进制字符串（对齐 Go generateToken）。
fn generate_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// 首启种子（对齐 Go SeedDefaults）：默认 API 令牌 + admin 账户。
/// 返回 (首启 API 明文令牌, 首启 admin 明文口令)，对应项已存在则为 None。
pub async fn seed_defaults(pool: &PgPool) -> Result<(Option<String>, Option<String>)> {
    let key_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_api_keys WHERE deleted_at IS NULL")
            .fetch_one(pool)
            .await?;
    let first_run_token = if key_count == 0 {
        let (token, _) = AdminApiKeyRepo::new(pool.clone()).create("default").await?;
        Some(token)
    } else {
        None
    };

    let admin_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM admin_accounts WHERE username = 'admin'")
            .fetch_one(pool)
            .await?;
    let first_run_password = if admin_count == 0 {
        let password = generate_token(16);
        let hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)?;
        sqlx::query("INSERT INTO admin_accounts (username, password_hash) VALUES ('admin', $1)")
            .bind(hash)
            .execute(pool)
            .await?;
        Some(password)
    } else {
        None
    };

    Ok((first_run_token, first_run_password))
}

/// 数据面默认站点种子（对齐 Go SeedDataplaneDefaults）。幂等：:80 已有站点则跳过。
pub async fn seed_dataplane_defaults(pool: &PgPool) -> Result<()> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sites WHERE bind = ':80' AND deleted_at IS NULL")
            .fetch_one(pool)
            .await?;
    if count > 0 {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO sites (host, upstream_urls, bind, enabled) VALUES ('*', $1, ':80', true)",
    )
    .bind("http://127.0.0.1:8080")
    .execute(pool)
    .await?;
    Ok(())
}
