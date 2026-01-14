use crate::auth::auth_config::TokenStorage;
use crate::store::local_storage::LocalStorage;
use crate::store::redis_storage::RedisStorage;
use crate::store::store_result::{StorageTrait, StorageResult};
use async_trait::async_trait;
use log::{debug, error};
use std::time::Duration;

/// 混合存储实现
///
/// 根据配置使用不同的存储策略：
/// - Memory: 只使用本地缓存
/// - Redis: 只使用Redis缓存
/// - All: 同时使用本地缓存和Redis缓存
///
/// ## 使用方式
/// ```rust,ignore
/// use crate::auth::auth_config::TokenStorage;
/// use crate::store::{HybridStorage, LocalStorage, RedisStorage};
/// use redis::aio::ConnectionManager;
///
/// // 创建本地缓存
/// let local_storage = LocalStorage::new(
///     Some("pocket:"),
///     10000,
///     Duration::from_secs(3600),
///     Duration::from_secs(1800),
/// );
///
/// // 创建Redis缓存
/// let redis_manager = ConnectionManager::new(redis::Client::open("redis://localhost:6379/0")?);
/// let redis_storage = RedisStorage::new(redis_manager, "pocket:".to_string());
///
/// // 创建混合存储（使用All策略）
/// let hybrid_storage = HybridStorage::new(local_storage, redis_storage, TokenStorage::All);
/// ```
#[derive(Clone)]
pub struct HybridStorage {
    /// 本地缓存
    local_storage: LocalStorage,
    /// Redis缓存
    redis_storage: RedisStorage,
    /// 存储策略
    storage_type: TokenStorage,
}

impl HybridStorage {
    /// 创建新的混合存储实例
    pub fn new(local_storage: LocalStorage, redis_storage: RedisStorage, storage_type: TokenStorage) -> Self {
        Self {
            local_storage,
            redis_storage,
            storage_type,
        }
    }
}

#[async_trait]
impl StorageTrait for HybridStorage {
    async fn get(&self, key: &str) -> StorageResult<Option<String>> {
        debug!("混合存储获取: {}, 存储类型: {:?}", key, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.get(key).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.get(key).await
            },
            TokenStorage::All => {
                // 混合存储策略：先从本地获取，本地未命中则从Redis获取并同步到本地
                let local_result = self.local_storage.get(key).await;
                match local_result {
                    Ok(Some(value)) => {
                        debug!("本地缓存命中: {}", key);
                        Ok(Some(value))
                    },
                    Ok(None) => {
                        debug!("本地缓存未命中，尝试从Redis获取: {}", key);
                        let redis_result = self.redis_storage.get(key).await;
                        match redis_result {
                            Ok(Some(value)) => {
                                debug!("Redis缓存命中，同步到本地缓存: {}", key);
                                let _ = self.local_storage.set(key, &value, None).await;
                                Ok(Some(value))
                            },
                            Ok(None) => {
                                debug!("Redis缓存也未命中: {}", key);
                                Ok(None)
                            },
                            Err(e) => {
                                error!("Redis缓存获取失败: {}, 错误: {:?}", key, e);
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("本地缓存获取失败: {}, 错误: {:?}", key, e);
                        // 本地缓存获取失败，尝试从Redis获取
                        self.redis_storage.get(key).await
                    },
                }
            },
        }
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<Duration>) -> StorageResult<()> {
        debug!("混合存储设置: {}, TTL: {:?}, 存储类型: {:?}", key, ttl, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.set(key, value, ttl).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.set(key, value, ttl).await
            },
            TokenStorage::All => {
                // 混合存储策略：先设置Redis，再设置本地缓存，保证一致性
                let redis_result = self.redis_storage.set(key, value, ttl).await;
                match redis_result {
                    Ok(_) => {
                        let local_result = self.local_storage.set(key, value, ttl).await;
                        match local_result {
                            Ok(_) => {
                                debug!("混合存储设置成功: {}", key);
                                Ok(())
                            },
                            Err(e) => {
                                error!("本地缓存设置失败: {}, 错误: {:?}", key, e);
                                // 本地缓存设置失败，尝试删除Redis缓存，保证一致性
                                let _ = self.redis_storage.delete(key).await;
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis缓存设置失败: {}, 错误: {:?}", key, e);
                        Err(e)
                    },
                }
            },
        }
    }

    async fn delete(&self, key: &str) -> StorageResult<()> {
        debug!("混合存储删除: {}, 存储类型: {:?}", key, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.delete(key).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.delete(key).await
            },
            TokenStorage::All => {
                // 混合存储策略：先删除Redis，再删除本地缓存
                let redis_result = self.redis_storage.delete(key).await;
                match redis_result {
                    Ok(_) => {
                        let local_result = self.local_storage.delete(key).await;
                        match local_result {
                            Ok(_) => {
                                debug!("混合存储删除成功: {}", key);
                                Ok(())
                            },
                            Err(e) => {
                                error!("本地缓存删除失败: {}, 错误: {:?}", key, e);
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis缓存删除失败: {}, 错误: {:?}", key, e);
                        // Redis删除失败，尝试删除本地缓存
                        let _ = self.local_storage.delete(key).await;
                        Err(e)
                    },
                }
            },
        }
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        debug!("混合存储检查存在: {}, 存储类型: {:?}", key, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.exists(key).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.exists(key).await
            },
            TokenStorage::All => {
                // 混合存储策略：先检查本地，本地不存在则检查Redis并同步到本地
                let local_result = self.local_storage.exists(key).await;
                match local_result {
                    Ok(true) => {
                        debug!("本地缓存存在: {}", key);
                        Ok(true)
                    },
                    Ok(false) => {
                        debug!("本地缓存不存在，检查Redis: {}", key);
                        let redis_result = self.redis_storage.exists(key).await;
                        match redis_result {
                            Ok(exists) => {
                                if exists {
                                    // Redis存在，同步到本地缓存
                                    if let Ok(Some(value)) = self.redis_storage.get(key).await {
                                        let _ = self.local_storage.set(key, &value, None).await;
                                    }
                                }
                                Ok(exists)
                            },
                            Err(e) => {
                                error!("Redis检查存在失败: {}, 错误: {:?}", key, e);
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("本地缓存检查存在失败: {}, 错误: {:?}", key, e);
                        // 本地缓存检查失败，检查Redis
                        self.redis_storage.exists(key).await
                    },
                }
            },
        }
    }

    async fn expire(&self, key: &str, ttl: Duration) -> StorageResult<()> {
        debug!("混合存储设置过期: {}, TTL: {:?}, 存储类型: {:?}", key, ttl, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.expire(key, ttl).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.expire(key, ttl).await
            },
            TokenStorage::All => {
                // 混合存储策略：先设置Redis过期时间，再设置本地缓存过期时间
                let redis_result = self.redis_storage.expire(key, ttl).await;
                match redis_result {
                    Ok(_) => {
                        let local_result = self.local_storage.expire(key, ttl).await;
                        match local_result {
                            Ok(_) => {
                                debug!("混合存储设置过期成功: {}", key);
                                Ok(())
                            },
                            Err(e) => {
                                error!("本地缓存设置过期失败: {}, 错误: {:?}", key, e);
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis设置过期失败: {}, 错误: {:?}", key, e);
                        Err(e)
                    },
                }
            },
        }
    }

    async fn ttl(&self, key: &str) -> StorageResult<Option<Duration>> {
        debug!("混合存储获取TTL: {}, 存储类型: {:?}", key, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.ttl(key).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.ttl(key).await
            },
            TokenStorage::All => {
                // 混合存储策略：取本地和Redis中较小的TTL值
                let local_result = self.local_storage.ttl(key).await;
                match local_result {
                    Ok(Some(local_ttl)) => {
                        debug!("本地缓存TTL: {}秒", local_ttl.as_secs());
                        let redis_result = self.redis_storage.ttl(key).await;
                        match redis_result {
                            Ok(Some(redis_ttl)) => {
                                // 取较小的TTL值
                                let min_ttl = std::cmp::min(local_ttl, redis_ttl);
                                debug!("Redis缓存TTL: {}秒，取较小值: {}秒", redis_ttl.as_secs(), min_ttl.as_secs());
                                Ok(Some(min_ttl))
                            },
                            Ok(None) => {
                                debug!("Redis缓存无TTL，使用本地缓存TTL: {}秒", local_ttl.as_secs());
                                Ok(Some(local_ttl))
                            },
                            Err(e) => {
                                error!("Redis获取TTL失败: {}, 错误: {:?}", key, e);
                                // Redis获取失败，使用本地缓存TTL
                                Ok(Some(local_ttl))
                            },
                        }
                    },
                    Ok(None) => {
                        debug!("本地缓存无TTL，从Redis获取: {}", key);
                        // 本地缓存无TTL，从Redis获取
                        self.redis_storage.ttl(key).await
                    },
                    Err(e) => {
                        error!("本地缓存获取TTL失败: {}, 错误: {:?}", key, e);
                        // 本地缓存获取失败，从Redis获取
                        self.redis_storage.ttl(key).await
                    },
                }
            },
        }
    }

    async fn mget(&self, keys: &[&str]) -> StorageResult<Vec<Option<String>>> {
        debug!("混合存储批量获取，共 {} 个键，存储类型: {:?}", keys.len(), self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.mget(keys).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.mget(keys).await
            },
            TokenStorage::All => {
                // 混合存储策略：对每个键使用get方法，保证一致性
                let mut results = Vec::with_capacity(keys.len());
                for key in keys {
                    let result = self.get(key).await?;
                    results.push(result);
                }
                debug!("混合存储批量获取完成");
                Ok(results)
            },
        }
    }

    async fn mset(&self, items: &[(&str, &str)], ttl: Option<Duration>) -> StorageResult<()> {
        debug!("混合存储批量设置，共 {} 个键值对，存储类型: {:?}", items.len(), self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.mset(items, ttl).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.mset(items, ttl).await
            },
            TokenStorage::All => {
                // 混合存储策略：先批量设置到Redis，再批量设置到本地缓存
                let redis_result = self.redis_storage.mset(items, ttl).await;
                match redis_result {
                    Ok(_) => {
                        let local_result = self.local_storage.mset(items, ttl).await;
                        match local_result {
                            Ok(_) => {
                                debug!("混合存储批量设置成功");
                                Ok(())
                            },
                            Err(e) => {
                                error!("本地缓存批量设置失败，错误: {:?}", e);
                                // 本地缓存设置失败，尝试回滚Redis
                                let keys: Vec<&str> = items.iter().map(|(k, _)| *k).collect();
                                let _ = self.redis_storage.mdel(&keys).await;
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis缓存批量设置失败，错误: {:?}", e);
                        Err(e)
                    },
                }
            },
        }
    }

    async fn mdel(&self, keys: &[&str]) -> StorageResult<()> {
        debug!("混合存储批量删除，共 {} 个键，存储类型: {:?}", keys.len(), self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.mdel(keys).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.mdel(keys).await
            },
            TokenStorage::All => {
                // 混合存储策略：先批量删除Redis，再批量删除本地缓存
                let redis_result = self.redis_storage.mdel(keys).await;
                match redis_result {
                    Ok(_) => {
                        let local_result = self.local_storage.mdel(keys).await;
                        match local_result {
                            Ok(_) => {
                                debug!("混合存储批量删除成功");
                                Ok(())
                            },
                            Err(e) => {
                                error!("本地缓存批量删除失败，错误: {:?}", e);
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis缓存批量删除失败，错误: {:?}", e);
                        // Redis删除失败，尝试删除本地缓存
                        let _ = self.local_storage.mdel(keys).await;
                        Err(e)
                    },
                }
            },
        }
    }

    async fn incr(&self, key: &str) -> StorageResult<i64> {
        debug!("混合存储原子递增: {}, 存储类型: {:?}", key, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.incr(key).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.incr(key).await
            },
            TokenStorage::All => {
                // 混合存储策略：先在Redis中递增，再同步到本地缓存
                let redis_result = self.redis_storage.incr(key).await;
                match redis_result {
                    Ok(new_value) => {
                        debug!("Redis原子递增成功，新值: {}", new_value);
                        // Redis递增成功，同步到本地缓存
                        let new_value_str = new_value.to_string();
                        let local_result = self.local_storage.set(key, &new_value_str, None).await;
                        match local_result {
                            Ok(_) => {
                                debug!("本地缓存同步递增结果成功: {}", key);
                                Ok(new_value)
                            },
                            Err(e) => {
                                error!("本地缓存同步递增结果失败: {}, 错误: {:?}", key, e);
                                // 本地缓存同步失败，不影响Redis结果，返回Redis结果
                                Ok(new_value)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis原子递增失败: {}, 错误: {:?}", key, e);
                        Err(e)
                    },
                }
            },
        }
    }

    async fn decr(&self, key: &str) -> StorageResult<i64> {
        debug!("混合存储原子递减: {}, 存储类型: {:?}", key, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.decr(key).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.decr(key).await
            },
            TokenStorage::All => {
                // 混合存储策略：先在Redis中递减，再同步到本地缓存
                let redis_result = self.redis_storage.decr(key).await;
                match redis_result {
                    Ok(new_value) => {
                        debug!("Redis原子递减成功，新值: {}", new_value);
                        // Redis递减成功，同步到本地缓存
                        let new_value_str = new_value.to_string();
                        let local_result = self.local_storage.set(key, &new_value_str, None).await;
                        match local_result {
                            Ok(_) => {
                                debug!("本地缓存同步递减结果成功: {}", key);
                                Ok(new_value)
                            },
                            Err(e) => {
                                error!("本地缓存同步递减结果失败: {}, 错误: {:?}", key, e);
                                // 本地缓存同步失败，不影响Redis结果，返回Redis结果
                                Ok(new_value)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis原子递减失败: {}, 错误: {:?}", key, e);
                        Err(e)
                    },
                }
            },
        }
    }

    async fn clear(&self) -> StorageResult<()> {
        debug!("混合存储清空，存储类型: {:?}", self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.clear().await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.clear().await
            },
            TokenStorage::All => {
                // 混合存储策略：先清空Redis，再清空本地缓存
                let redis_result = self.redis_storage.clear().await;
                match redis_result {
                    Ok(_) => {
                        let local_result = self.local_storage.clear().await;
                        match local_result {
                            Ok(_) => {
                                debug!("混合存储清空成功");
                                Ok(())
                            },
                            Err(e) => {
                                error!("本地缓存清空失败，错误: {:?}", e);
                                Err(e)
                            },
                        }
                    },
                    Err(e) => {
                        error!("Redis缓存清空失败，错误: {:?}", e);
                        // Redis清空失败，尝试清空本地缓存
                        let _ = self.local_storage.clear().await;
                        Err(e)
                    },
                }
            },
        }
    }

    async fn keys(&self, pattern: &str) -> StorageResult<Vec<String>> {
        debug!("混合存储获取匹配键: {}, 存储类型: {:?}", pattern, self.storage_type);

        match self.storage_type {
            TokenStorage::Memory => {
                // 只使用本地缓存
                self.local_storage.keys(pattern).await
            },
            TokenStorage::Redis => {
                // 只使用Redis缓存
                self.redis_storage.keys(pattern).await
            },
            TokenStorage::All => {
                // 混合存储策略：从Redis获取匹配键，Redis失败则从本地获取
                let redis_result = self.redis_storage.keys(pattern).await;
                match redis_result {
                    Ok(keys) => {
                        debug!("从Redis获取匹配键 {} 个: {:?}", keys.len(), keys);
                        Ok(keys)
                    },
                    Err(e) => {
                        error!("Redis获取匹配键失败，错误: {:?}", e);
                        // Redis获取失败，尝试从本地缓存获取
                        self.local_storage.keys(pattern).await
                    },
                }
            },
        }
    }
}
