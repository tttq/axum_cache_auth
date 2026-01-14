//! 存储适配器trait定义

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

pub type StorageResult<T> = Result<T, StorageError>;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Storage operation failed: {0}")]
    OperationFailed(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

/// 存储适配器trait
///
/// 所有存储实现（内存、Redis、数据库等）都需要实现这个trait
#[async_trait]
pub trait StorageTrait: Send + Sync {
    /// 获取值
    async fn get(&self, key: &str) -> StorageResult<Option<String>>;

    /// 设置值
    ///
    /// # 参数
    /// * `key` - 键
    /// * `value` - 值
    /// * `ttl` - 过期时间（None表示永不过期）
    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()>;

    /// 删除值
    async fn delete(&self, key: &str) -> StorageResult<()>;

    /// 检查键是否存在
    async fn exists(&self, key: &str) -> StorageResult<bool>;

    /// 设置过期时间
    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()>;

    /// 获取剩余过期时间
    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>>;

    /// 批量获取
    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key).await?);
        }
        Ok(results)
    }

    /// 批量设置
    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        for (key, value) in items {
            self.set(key, value, ttl).await?;
        }
        Ok(())
    }

    /// 批量删除
    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        for key in keys {
            self.delete(key).await?;
        }
        Ok(())
    }

    /// 原子递增
    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let current = self.get(key).await?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let new_value = current + 1;
        self.set(key, &new_value.to_string(), None).await?;
        Ok(new_value)
    }

    /// 原子递减
    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let current = self.get(key).await?
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        let new_value = current - 1;
        self.set(key, &new_value.to_string(), None).await?;
        Ok(new_value)
    }

    /// 清空所有数据（谨慎使用）
    async fn clear(&self) -> StorageResult<()>;

    /// 获取匹配模式的所有键
    ///
    /// # 参数
    /// * `pattern` - 匹配模式，支持 * 通配符
    async fn keys(&self, _pattern: &str) -> StorageResult<Vec<String>> {
        // 默认实现：不支持模式匹配，返回空列表
        Ok(Vec::new())
    }
}
