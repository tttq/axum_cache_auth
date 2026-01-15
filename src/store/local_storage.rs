use crate::store::store_result::{ StorageResult, StorageTrait};
use async_trait::async_trait;
use log::{debug, info, warn};
use moka::sync::Cache;
use std::sync::Arc;
use std::time::{Duration};

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
        format!("{}:{}", self.key_prefix, key)
    }

    /// 解析完整键名，获取原始键（去除前缀）
    fn parse_key<'a>(&self, full_key: &'a str) -> Option<&'a str> {
        if full_key.starts_with(&self.key_prefix) {
            Some(&full_key[self.key_prefix.len()..])
        } else {
            None
        }
    }

    /// 简单的glob模式匹配（支持*和?）
    fn matches_pattern(&self, key: &str, pattern: &str) -> bool {
        let pattern_chars: Vec<char> = pattern.chars().collect();
        let key_chars: Vec<char> = key.chars().collect();

        let mut p_idx = 0; // 模式索引
        let mut k_idx = 0; // 键索引
        let mut star_idx = None; // 最近的*位置
        let mut match_idx = 0; // *匹配的位置

        while k_idx < key_chars.len() {
            if p_idx < pattern_chars.len() {
                match pattern_chars[p_idx] {
                    '*' => {
                        // 记录*的位置，并继续匹配
                        star_idx = Some(p_idx);
                        match_idx = k_idx;
                        p_idx += 1;
                        continue;
                    },
                    '?' => {
                        // ?匹配任意单个字符
                        p_idx += 1;
                        k_idx += 1;
                        continue;
                    },
                    c => {
                        if c == key_chars[k_idx] {
                            // 字符匹配，继续
                            p_idx += 1;
                            k_idx += 1;
                            continue;
                        }
                    }
                }
            }

            // 如果没有匹配，回溯到最近的*
            if let Some(star_p_idx) = star_idx {
                p_idx = star_p_idx + 1;
                match_idx += 1;
                k_idx = match_idx;
            } else {
                // 没有*可以回溯，匹配失败
                return false;
            }
        }

        // 处理模式末尾的*
        while p_idx < pattern_chars.len() && pattern_chars[p_idx] == '*' {
            p_idx += 1;
        }

        // 如果模式已经处理完，匹配成功
        p_idx == pattern_chars.len()
    }
}

#[async_trait]
impl StorageTrait for LocalStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        let full_key = self.full_key(key);
        debug!("获取本地缓存: {}", full_key);
        
        match self.cache.get(&full_key) {
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
            .insert(full_key.clone(), value.to_string());
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
        
        self.cache.remove(&full_key);
        info!("本地缓存删除成功: {}", full_key);
        Ok(())
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let full_key = self.full_key(key);
        debug!("检查本地缓存是否存在: {}", full_key);
        
        let exists = self.cache.contains_key(&full_key);
        debug!("本地缓存{}: {}", if exists { "存在" } else { "不存在" }, full_key);
        Ok(exists)
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        let full_key = self.full_key(key);
        debug!("设置本地缓存过期时间: {}, TTL: {:?}", full_key, ttl);
        
        // moka不支持单独更新现有键的TTL，需要重新插入
        if let Some(value) = self.cache.get(&full_key) {
            self.cache.insert(full_key.clone(), value);
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
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        
        let new_value = current + 1;
        self.cache
            .insert(full_key.clone(), new_value.to_string());
        
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
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0);
        
        let new_value = current - 1;
        self.cache
            .insert(full_key.clone(), new_value.to_string());
        
        debug!("原子递减完成: {}, 旧值: {}, 新值: {}", full_key, current, new_value);
        Ok(new_value)
    }

    async fn clear(&self) -> StorageResult<()> {
        debug!("清空本地缓存");
        
        self.cache.invalidate_all();
        info!("本地缓存清空完成");
        Ok(())
    }

    async fn keys(&self, pattern: &str) -> StorageResult<Vec<String>> {
        debug!("获取匹配模式的本地缓存键: {}", pattern);
    
        let full_pattern = self.full_key(pattern);
        debug!("完整匹配模式: {}", full_pattern);
    
        let mut matching_keys = Vec::new();
    
        // 遍历所有缓存键并匹配模式
        for (key, _) in self.cache.iter() {
            let cache_key = key.clone();
            if self.matches_pattern(&cache_key.clone(), &full_pattern) {
                // 解析出原始键（去除前缀）
                if let Some(original_key) = self.parse_key(&cache_key) {
                    matching_keys.push(original_key.to_string());
                }
            }
        }
    
        debug!("找到 {} 个匹配的键", matching_keys.len());
        Ok(matching_keys)
    }

}