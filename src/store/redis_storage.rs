//! # pocket-storage-redis
//!
//! Redis存储实现
//!
//! 适用于：
//! - 分布式部署
//! - 需要数据持久化
//! - 高性能要求的场景
//!
//! ## 使用方式
//!
//! ### 方式 1: 使用 Redis URL
//! ```rust,ignore
//! use sa_token_storage_redis::RedisStorage;
//!
//! // 无密码
//! let storage = RedisStorage::new("redis://localhost:6379/0", "pocket:").await?;
//!
//! // 有密码
//! let storage = RedisStorage::new("redis://:password@localhost:6379/0", "pocket:").await?;
//! ```
//!
//! ### 方式 2: 使用配置结构体
//! ```rust,ignore
//! use sa_token_storage_redis::{RedisStorage, RedisConfig};
//!
//! let config = RedisConfig {
//!     host: "localhost".to_string(),
//!     port: 6379,
//!     password: Some("your-password".to_string()),
//!     database: 0,
//!     pool_size: 10,
//! };
//!
//! let storage = RedisStorage::from_config(config, "pocket:").await?;
//! ```

use crate::store::store_result::{StorageError, StorageResult, StorageTrait};
use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::Duration;
/// Redis存储实现
#[derive(Clone)]
pub struct RedisStorage {
    client: ConnectionManager,
    key_prefix: String,
}
impl RedisStorage {
    pub fn new(client: ConnectionManager, key_prefix: String) ->RedisStorage{
        Self{
            client,
            key_prefix,
        }
    }
    
    /// 生成完整的键名（包含前缀）
    fn full_key(&self, key: &str) -> String {
        format!("{}:{}", self.key_prefix, key)
    }
}

#[async_trait]
impl StorageTrait for RedisStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.get(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        if let Some(ttl) = ttl {
            conn.set_ex(&full_key, value, ttl.as_secs()).await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))
        } else {
            conn.set(&full_key, value).await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.del(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.exists(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.expire(&full_key, ttl.as_secs() as i64).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        let ttl_secs: i64 = conn.ttl(&full_key).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        match ttl_secs {
            -2 => Ok(None), // 键不存在
            -1 => Ok(None), // 永不过期
            secs if secs > 0 => Ok(Some(Duration::from_secs(secs as u64))),
            _ => Ok(Some(Duration::from_secs(0))),
        }
    }

    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let mut conn = self.client.clone();
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();

        conn.mget(&full_keys).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_items: Vec<(String, &str)> = items.iter()
            .map(|(k, v)| (self.full_key(k), *v))
            .collect();

        // 使用 pipeline 批量操作
        let mut pipe = redis::pipe();
        for (key, value) in &full_items {
            if let Some(ttl) = ttl {
                pipe.set_ex(key, *value, ttl.as_secs());
            } else {
                pipe.set(key, *value);
            }
        }

        pipe.query_async(&mut conn).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();

        conn.del(&full_keys).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.incr(&full_key, 1).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let mut conn = self.client.clone();
        let full_key = self.full_key(key);

        conn.decr(&full_key, 1).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))
    }

    async fn clear(&self) -> StorageResult<()> {
        let mut conn = self.client.clone();
        let pattern = format!("{}*", self.key_prefix);

        // 获取所有匹配的键
        let keys: Vec<String> = conn.keys(&pattern).await
            .map_err(|e| StorageError::OperationFailed(e.to_string()))?;

        if !keys.is_empty() {
            conn.del::<_, ()>(&keys).await
                .map_err(|e| StorageError::OperationFailed(e.to_string()))?;
        }

        Ok(())
    }
}
