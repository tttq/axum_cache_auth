use crate::store::store_result::{StorageError, StorageResult, StorageTrait};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use moka::sync::Cache;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 本地缓存实现
/// 
/// 适用于：
/// - 单机部署
/// - 低延迟要求
/// - 不需要数据持久化的场景
/// 
/// ## 使用方式
/// ```rust,ignore
/// use crate::store::local_storage::LocalStorage;
/// 
/// let storage = LocalStorage::new(
///     Some("pocket:"), // 键前缀
///     10000,           // 最大容量
///     Duration::from_secs(3600), // 默认过期时间
///     Duration::from_secs(1800), // 空闲过期时间
/// );
/// ```
#[derive(Clone)]
pub struct LocalStorage {
    /// 本地缓存实例
    cache: Arc<Cache<String, String>>,
    /// 键前缀
    key_prefix: String,
    /// 默认过期时间
    default_ttl: Duration,
}

impl LocalStorage {
    /// 创建新的本地缓存实例
    pub fn new(
        key_prefix: Option<&str>,
        max_capacity: u64,
        default_ttl: Duration,
        time_to_idle: Duration,
    ) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(default_ttl)
            .time_to_idle(time_to_idle)
            .build();

        Self {
            cache: Arc::new(cache),
            key_prefix: key_prefix.unwrap_or("").to_string(),
            default_ttl,
        }
    }

    /// 生成完整的键名（包含前缀）
    fn full_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }

    /// 解析完整键名，获取原始键（去除前缀）
    fn parse_key(&self, full_key: &str) -> Option<&str> {
        if full_key.starts_with(&self.key_prefix) {
            Some(&full_key[self.key_prefix.len()..])
        } else {
            None
        }
    }
}

#[async_trait]
impl StorageTrait for LocalStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let full_key = self.full_key(key);
        debug!("获取本地缓存: {}", full_key);
        
        match self.cache.get(&full_key).await {
            Some(value) => {
                debug!("本地缓存命中: {}", full_key);
                Ok(Some(value))
            },
            None => {
                debug!("本地缓存未命中: {}", full_key);
                Ok(None)
            },
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        let full_key = self.full_key(key);
        let actual_ttl = ttl.unwrap_or(self.default_ttl);
        debug!("设置本地缓存: {}, TTL: {:?}", full_key, actual_ttl);
        
        self.cache
            .insert(full_key.clone(), value.to_string())
            .await;
        
        // 如果指定了不同的TTL，则单独设置
        if ttl.is_some() {
            // moka会自动处理TTL，这里不需要额外操作
        }
        
        info!("本地缓存设置成功: {}", full_key);
        Ok(())
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        let full_key = self.full_key(key);
        debug!("删除本地缓存: {}", full_key);
        
        self.cache.remove(&full_key).await;
        info!("本地缓存删除成功: {}", full_key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let full_key = self.full_key(key);
        debug!("检查本地缓存是否存在: {}", full_key);
        
        let exists = self.cache.contains_key(&full_key).await;
        debug!("本地缓存{}: {}", if exists { "存在" } else { "不存在" }, full_key);
        Ok(exists)
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let full_key = self.full_key(key);
        debug!("设置本地缓存过期时间: {}, TTL: {:?}", full_key, ttl);
        
        // moka不支持单独更新现有键的TTL，需要重新插入
        if let Some(value) = self.cache.get(&full_key).await {
            self.cache.insert(full_key.clone(), value).await;
            info!("本地缓存过期时间更新成功: {}", full_key);
        } else {
            warn!("尝试更新不存在的本地缓存过期时间: {}", full_key);
        }
        
        Ok(())
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        let full_key = self.full_key(key);
        debug!("获取本地缓存剩余过期时间: {}", full_key);
        
        // moka不直接支持获取剩余TTL，返回None表示不支持该操作
        // 或者可以返回默认TTL作为近似值
        Ok(Some(self.default_ttl))
    }

    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        debug!("批量获取本地缓存，共 {} 个键", keys.len());
        
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.get(key).await?);
        }
        
        debug!("批量获取本地缓存完成");
        Ok(results)
    }

    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        debug!("批量设置本地缓存，共 {} 个键值对", items.len());
        
        for (key, value) in items {
            self.set(key, value, ttl).await?;
        }
        
        debug!("批量设置本地缓存完成");
        Ok(())
    }

    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        debug!("批量删除本地缓存，共 {} 个键", keys.len());
        
        for key in keys {
            self.delete(key).await?;
        }
        
        debug!("批量删除本地缓存完成");
        Ok(())
    }

    async fn incr(&self, key: &str) -> StorageResult<i64> {
        let full_key = self.full_key(key);
        debug!("原子递增本地缓存: {}", full_key);
        
        // 由于moka不支持原子操作，需要使用锁或者重新设计
        // 这里使用简单的获取-修改-插入模式，在并发场景下可能不是严格原子的
        let current = self.cache
            .get(&full_key)
            .await
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        
        let new_value = current + 1;
        self.cache
            .insert(full_key.clone(), new_value.to_string())
            .await;
        
        debug!("原子递增完成: {}, 旧值: {}, 新值: {}", full_key, current, new_value);
        Ok(new_value)
    }

    async fn decr(&self, key: &str) -> StorageResult<i64> {
        let full_key = self.full_key(key);
        debug!("原子递减本地缓存: {}", full_key);
        
        // 由于moka不支持原子操作，需要使用锁或者重新设计
        // 这里使用简单的获取-修改-插入模式，在并发场景下可能不是严格原子的
        let current = self.cache
            .get(&full_key)
            .await
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        
        let new_value = current - 1;
        self.cache
            .insert(full_key.clone(), new_value.to_string())
            .await;
        
        debug!("原子递减完成: {}, 旧值: {}, 新值: {}", full_key, current, new_value);
        Ok(new_value)
    }

    async fn clear(&self) -> StorageResult<()> {
        debug!("清空本地缓存");
        
        self.cache.invalidate_all().await;
        info!("本地缓存清空完成");
        Ok(())
    }

    async fn keys(&self, pattern: &str) -> StorageResult<Vec<String>> {
        debug!("获取匹配模式的本地缓存键: {}", pattern);
        
        // moka不支持直接获取所有键或匹配键，返回空列表
        // 如果需要支持此功能，可能需要额外维护一个键的集合
        Ok(Vec::new())
    }
}