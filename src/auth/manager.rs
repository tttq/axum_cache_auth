//! Token 管理器 - sa-token 的核心入口

use crate::auth::auth_config::AuthConfig;
use crate::auth::error::{TokenError, TokenResult};
use crate::auth::layer::AuthValidTrait;
use crate::auth::token::generator::TokenGenerator;
use crate::auth::token::{TokenInfo, TokenValue};
use crate::store::hybrid_storage::HybridStorage;
use crate::store::store_result::StorageTrait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 自定义和token一起续期的方法，需要将 auto_renew 设置为true才剩下
pub trait CustomTimeoutTrait: Send + Sync {
    // 自定义和token一起存储等续期的方法
    fn renew_custom_timeout(&self,login_id:Option< String>,client_id:Option<String>,tenant_id:Option<String>, timeout:u64)-> Result<(),TokenError>;
}

/// sa-token 管理器
#[derive(Clone)]
pub struct TokenManager {
    pub storage: Arc<HybridStorage>,
    pub auth_valid_trait:Arc<dyn AuthValidTrait>,
    pub config: Arc<AuthConfig>,
    pub custom_timeout_trait: Option<Arc<dyn CustomTimeoutTrait>>,
}

impl TokenManager {
    /// 创建新的管理器实例
    pub fn new(storage: Arc<HybridStorage>, config: Arc<AuthConfig>, auth_valid_trait:Arc<dyn AuthValidTrait>,custom_timeout_trait: Option<Arc<dyn CustomTimeoutTrait>>) -> Self {
        Self { storage, config ,auth_valid_trait,custom_timeout_trait}
    }
    /// 登录：为指定账号创建 token
    pub async fn login(&self, login_id: impl Into<String>) -> TokenResult<TokenValue> {
        self.login_with_options(login_id, None, None, None, None, None)
            .await
    }

    pub async fn login_with_client_options(
        &self,
        login_id: impl Into<String>,
        login_type: Option<String>,
        device: Option<String>,
        extra_data: Option<serde_json::Value>,
        nonce: Option<String>,
        expire_time: Option<DateTime<Utc>>,
        client_id: Option<String>,
        tenant_id: Option<String>,
    ) -> TokenResult<TokenValue> {
        let login_id = login_id.into();

        // 生成 token（支持 JWT）
        let token = TokenGenerator::generate_with_login_id(&self.config, &login_id);

        // 创建 token 信息
        let mut token_info = TokenInfo::new(token.clone(), login_id.clone());

        // 设置登录类型
        token_info.login_type = login_type.unwrap_or_else(|| "default".to_string());

        // 设置设备标识
        if let Some(device_str) = device {
            token_info.device = Some(device_str);
        }

        // 设置额外数据
        if let Some(extra) = extra_data {
            token_info.extra_data = Some(extra);
        }

        // 设置 nonce
        if let Some(nonce_str) = nonce {
            token_info.nonce = Some(nonce_str);
        }

        // 设置过期时间
        if let Some(custom_expire_time) = expire_time {
            token_info.expire_time = Some(custom_expire_time);
        }
        // 设置客户端id
        if let Some(client_id) = client_id {
            token_info.client_id = Some(client_id);
        }
        // 设置租户
        if let Some(tenant_id) = tenant_id {
            token_info.tenant_id = Some(tenant_id);
        }
        // 调用底层方法
        self.login_with_token_info(token_info).await
    }

    /// 登录：为指定账号创建 token（支持自定义 TokenInfo 字段）
    ///
    /// # 参数 | Parameters
    /// * `login_id` - 登录用户 ID | Login user ID
    /// * `login_type` - 登录类型（如 "user", "admin"）| Login type (e.g., "user", "admin")
    /// * `device` - 设备标识 | Device identifier
    /// * `extra_data` - 额外数据 | Extra data
    /// * `nonce` - 防重放攻击的一次性令牌 | One-time token for replay attack prevention
    /// * `expire_time` - 自定义过期时间（如果为 None，则使用配置的过期时间）| Custom expiration time (if None, use configured timeout)
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// let token = manager.login_with_options(
    ///     "user_123",
    ///     Some("admin".to_string()),
    ///     Some("iPhone".to_string()),
    ///     Some(json!({"ip": "192.168.1.1"})),
    ///     Some("nonce_123".to_string()),
    ///     None,
    /// ).await?;
    /// ```
    pub async fn login_with_options(
        &self,
        login_id: impl Into<String>,
        login_type: Option<String>,
        device: Option<String>,
        extra_data: Option<serde_json::Value>,
        nonce: Option<String>,
        expire_time: Option<DateTime<Utc>>,
    ) -> TokenResult<TokenValue> {
        let login_id = login_id.into();

        // 生成 token（支持 JWT）
        let token = TokenGenerator::generate_with_login_id(&self.config, &login_id);

        // 创建 token 信息
        let mut token_info = TokenInfo::new(token.clone(), login_id.clone());

        // 设置登录类型
        token_info.login_type = login_type.unwrap_or_else(|| "default".to_string());

        // 设置设备标识
        if let Some(device_str) = device {
            token_info.device = Some(device_str);
        }

        // 设置额外数据
        if let Some(extra) = extra_data {
            token_info.extra_data = Some(extra);
        }

        // 设置 nonce
        if let Some(nonce_str) = nonce {
            token_info.nonce = Some(nonce_str);
        }

        // 设置过期时间
        if let Some(custom_expire_time) = expire_time {
            token_info.expire_time = Some(custom_expire_time);
        }
        // 注意：如果 expire_time 为 None，login_with_token_info 会自动使用配置的过期时间

        // 调用底层方法
        self.login_with_token_info(token_info).await
    }

    /// 登录：使用完整的 TokenInfo 对象创建 token
    ///
    /// # 参数 | Parameters
    /// * `token_info` - 完整的 TokenInfo 对象，包含所有 token 信息 | Complete TokenInfo object containing all token information
    ///
    /// # 说明 | Notes
    /// * TokenInfo 中的 `token` 字段将被使用（如果已设置），否则会自动生成
    /// * TokenInfo 中的 `login_id` 字段必须设置
    /// * 如果 `expire_time` 为 None，将使用配置的过期时间
    /// * The `token` field in TokenInfo will be used (if set), otherwise will be auto-generated
    /// * The `login_id` field in TokenInfo must be set
    /// * If `expire_time` is None, will use configured timeout
    ///
    /// # 示例 | Example
    /// ```rust,ignore
    /// use sa_token_core::token::{TokenInfo, TokenValue};
    /// use chrono::Utc;
    ///
    /// let mut token_info = TokenInfo::new(
    ///     TokenValue::new("custom_token_123"),
    ///     "user_123"
    /// );
    /// token_info.login_type = "admin".to_string();
    /// token_info.device = Some("iPhone".to_string());
    /// token_info.extra_data = Some(json!({"ip": "192.168.1.1"}));
    ///
    /// let token = manager.login_with_token_info(token_info).await?;
    /// ```
    pub async fn login_with_token_info(
        &self,
        mut token_info: TokenInfo,
    ) -> TokenResult<TokenValue> {
        let login_id = token_info.login_id.clone();

        // 如果 token_info 中没有 token，则生成一个
        let token = if token_info.token.as_str().is_empty() {
            TokenGenerator::generate_with_login_id(&self.config, &login_id)
        } else {
            token_info.token.clone()
        };

        // 更新 token_info 中的 token
        token_info.token = token.clone();

        // 更新最后活跃时间为当前时间
        token_info.update_active_time();

        // 如果过期时间为 None，使用配置的过期时间
        let now = Utc::now();
        if token_info.expire_time.is_none() {
            let timeout = self.config.expire;
            token_info.expire_time = Some(now + Duration::seconds(timeout as i64));
        }
        let store_name = self.config.cache_token_key.clone().unwrap_or_default();
        // 确保登录类型不为空
        if token_info.login_type.is_empty() {
            token_info.login_type = "default".to_string();
        }
        // 存储 token 信息
        let key = format!("{}:{}",store_name, token.as_str());
        let value =
            serde_json::to_string(&token_info).map_err(|e| TokenError::SerializationError(e))?;

        self.storage
            .set(&key, &value, self.config.timeout_duration())
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;

        // 保存 login_id 到 token 的映射（用于根据 login_id 查找 token）
        // 如果 login_type 不为空，使用包含 login_type 的 key 格式避免冲突
        // If login_type is not empty, use key format with login_type to avoid conflicts
        let login_token_key =
            if !token_info.login_type.is_empty() && token_info.login_type != "default" {
                format!("{}:{}:{}",store_name, login_id, token_info.login_type)
            } else {
                format!("{}:{}",store_name, login_id)
            };
        self.storage
            .set(
                &login_token_key,
                token.as_str(),
                self.config.timeout_duration(),
            )
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;

        // 如果不允许并发登录，踢掉之前的 token
        if !self.config.is_concurrent {
            self.logout_by_login_id(&login_id, token_info.client_id.unwrap_or_default().as_str()).await?;
        }
        Ok(token)
    }

    /// 登出：删除指定 token
    pub async fn logout(&self, token: &TokenValue) -> TokenResult<()> {
        log::debug!("Manager: 开始 logout，token: {}", token);
        // 先从存储获取 token 信息，用于触发事件（不调用 get_token_info 避免递归）
        let store_name = self.config.cache_token_key.clone().unwrap_or_default();
        let key = format!("{}:{}",store_name, token.as_str());
        log::debug!("Manager: 查询 token 信息，key: {}", key);
        let token_info_str = self
            .storage
            .get(&key)
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;
        let token_info = if let Some(value) = token_info_str {
            log::debug!("Manager: 找到 token 信息: {}", value);
            serde_json::from_str::<TokenInfo>(&value).ok()
        } else {
            log::debug!("Manager: 未找到 token 信息");
            None
        };

        // 如果有 token 信息，触发相关清理
        if let Some(info) = token_info {
            log::debug!(
                "Manager: 触发登出事件，login_id: {}, login_type: {}",
                info.login_id,
                info.login_type
            );
            // 这里可以添加其他登出事件处理，但不调用 logout_by_login_id 以避免递归
            match self.logout_by_login_id(&info.login_id, &info.client_id.unwrap_or_default()).await {
                Ok(()) => log::debug!("{:?}退出登出成功",info.login_id),
                Err(_err) =>  log::error!("{:?}退登出失败",info.login_id)
            }
            // 如果有设置登录类型
            if info.login_type.is_empty() {
                let login_type_key = format!("{}:{}:{}",store_name, info.login_id,info.login_type);
                self.storage.delete(&login_type_key).await
                    .map_err(|e| TokenError::StorageError(e.to_string()))?;
            }
        }
        // 清理在线 token
        self.storage.delete(&key).await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;
        log::debug!("Manager: logout 完成，token: {}", token);
        Ok(())
    }

    /// 根据登录 ID 登出所有 token
    pub async fn logout_by_login_id(&self, login_id: &str,client_id:&str) -> TokenResult<()> {
        match self.clean_permission(login_id, client_id).await{
            Ok(_) => {
                log::debug!("Manager: 删除用户权限成功，login_id: {}", login_id);
            },
            Err(e) => {
                log::error!("Manager: 删除用户权限失败，login_id: {}, error: {}", login_id, e);
            }
        };
        match self.clean_role(login_id, client_id).await{
            Ok(_) => {
                log::debug!("Manager: 删除用户角色成功，login_id: {}", login_id);
            },
            Err(e) => {
                log::error!("Manager: 删除用户角色失败，login_id: {}, error: {}", login_id, e);
            }
        };

        // 清理用户token
        let cache_token_key = self.config.cache_token_key.clone().unwrap_or_default();
        let token_pattern = format!("{cache_token_key}:{login_id}:*");
        log::info!("Clearing token_pattern cache pattern: {:?}", token_pattern);
        match self.storage.keys(&token_pattern).await {
            Ok(keys) => {
                log::info!("Clearing token cache for user: {:?}", login_id);
                log::info!("Clearing token cache for user: {:?}", keys);
                if !keys.is_empty() {
                    // Convert Vec<String> to Vec<&str>
                    let keys_ref: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
                    let _ = self.storage.mdel(&keys_ref).await;
                }
                Ok(())
            }
            Err(e) => {
                log::warn!("Failed to get menu cache keys: {:?}", e);
                Ok(())
            }
        }

    }

    /// 获取 token 信息
    pub async fn get_token_info(&self, token: &TokenValue) -> TokenResult<TokenInfo> {
        let store_name = self.config.cache_token_key.clone().unwrap_or_default();
        let key = format!("{}:{}",store_name, token.as_str());
        let value = self
            .storage
            .get(&key)
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?
            .ok_or(TokenError::TokenNotFound)?;

        let token_info: TokenInfo =
            serde_json::from_str(&value).map_err(|e| TokenError::SerializationError(e))?;

        // 检查是否过期
        if token_info.is_expired() {
            // 删除过期的 token
            self.logout(token).await?;
            return Err(TokenError::TokenExpired);
        }

        // 如果开启了自动续签，则自动续签
        // 注意：为了避免递归调用 get_token_info，这里直接更新过期时间
        if self.config.auto_renew {
            let renew_timeout = if self.config.active_timeout > 0 {
                self.config.active_timeout
            } else {
                self.config.expire
            };

            // 只有当token快要到期时才进行续签
            // 计算剩余时间，如果剩余时间小于等于续签时间的一半，则续签
            if let Some(expire_time) = token_info.expire_time {
                let now = Utc::now();
                let remaining = expire_time - now;
                // 如果剩余时间小于等于续签时间的一半，则执行续签
                if remaining <= Duration::seconds((renew_timeout / 2) as i64) {
                    // 直接续签（不递归调用 get_token_info）
                    let _ = self
                        .renew_timeout_internal(token, renew_timeout, &token_info)
                        .await;
                    // 调用时检查是否存在并调用
                    if let Some(custom_trait) = self.custom_timeout_trait.clone() {
                        // 更新自定义timeout
                        let client_id = token_info.client_id.clone();
                        let tenant_id = token_info.tenant_id.clone();
                        let login_id = token_info.login_id.clone();
                        let timeout = renew_timeout;
                        let _ = custom_trait.renew_custom_timeout(client_id, tenant_id, Some(login_id), timeout);
                    }
                }
            }
        }
        Ok(token_info)
    }

    /// 检查 token 是否有效
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.get_token_info(token).await.is_ok()
    }

    /// 通用续期方法：传入key和时间(秒)对key续期，如果key不存在则直接忽略，存在就续期
    pub async fn renew_timeout(&self, key: &str, timeout_seconds: u64) -> TokenResult<()> {
        // 1. 检查key是否存在
        if let Ok(Some(value)) = self.storage.get(key).await {
            // 2. 如果存在，使用新的过期时间重新设置
            let timeout = std::time::Duration::from_secs(timeout_seconds);
            self.storage
                .set(key, &value, Some(timeout))
                .await
                .map_err(|e| TokenError::StorageError(e.to_string()))?;
        }
        // 3. 如果不存在，直接返回成功
        Ok(())
    }
    /// 给内置的缓存数据续期
    async fn renew_timeout_internal(&self,
        token: &TokenValue,
        timeout_seconds: u64,
        token_info: &TokenInfo,){
        let client_id = token_info.client_id.clone().unwrap_or_default();
        let login_id = token_info.login_id.clone();
        let client_id_or_null = self.process_client_id(&client_id);
            // token续期
        let _= self.renew_timeout_token(token, timeout_seconds, token_info).await;
        // 权限续期
        let permission_key = self.config.cache_permission_key.clone().unwrap_or_default();
        let permission_cache_key = format!("{permission_key}:{}:{}",login_id,client_id_or_null);
        let _= self.renew_timeout(&permission_cache_key, timeout_seconds).await;
        // 角色续期
        let role_key = self.config.cache_role_key.clone().unwrap_or_default();
        let role_cache_key = format!("{role_key}:{}:{}",login_id,client_id_or_null);
        let _= self.renew_timeout(&role_cache_key, timeout_seconds).await;
    }

    /// 内部续期方法（避免递归调用 get_token_info）
    pub async fn renew_timeout_token(
        &self,
        token: &TokenValue,
        timeout_seconds: u64,
        token_info: &TokenInfo,
    ) -> TokenResult<()> {
        let mut new_token_info = token_info.clone();
        // 设置新的过期时间
        use chrono::{Duration, Utc};
        let new_expire_time = Utc::now() + Duration::seconds(timeout_seconds as i64);
        new_token_info.expire_time = Some(new_expire_time);
        let store_name = self.config.cache_token_key.clone().unwrap_or_default();
        // 保存更新后的 token 信息
        let key = format!("{}:{}",store_name, token.as_str());
        let value = serde_json::to_string(&new_token_info)
            .map_err(|e| TokenError::SerializationError(e))?;

        let timeout = std::time::Duration::from_secs(timeout_seconds);
        self.storage
            .set(&key, &value, Some(timeout))
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// 踢人下线
    pub async fn kick_out(&self, login_id: &str,client_id: &str) -> TokenResult<()> {
        let client_id_or_null =self.process_client_id(client_id);
        let token_result = self
            .storage
            .get(&format!("sa:login:token:{}", login_id))
            .await;
        match token_result {
            Ok(_token) =>  self.logout_by_login_id(login_id,client_id).await?,
            Err(_) => log::warn!("Manager: 用户不在线，login_id: {}, client_id: {}", login_id, client_id_or_null)
        }
        Ok(())
    }
    // ==================== 辅助方法 ====================
    
    /// 处理 client_id，将空字符串或 "*" 转换为 "*"
    fn process_client_id<'a>(&self, client_id: &'a str) -> &'a str {
        if !client_id.is_empty() && client_id != "*" {
            client_id
        } else {
            "*"
        }
    }
    
    /// 构建缓存键
    fn build_cache_key(&self, base_key: &str, login_id: &str, client_id: &str) -> String {
        let client_id_or_null = self.process_client_id(client_id);
        format!("{base_key}:{login_id}:{client_id_or_null}")
    }
    
    /// 通用设置缓存方法
    async fn set_cache<T: Serialize>(&self, base_key: &str, login_id: &str, client_id: &str, data: T, timeout: u64) -> TokenResult<()>
    {
        let cache_key = self.build_cache_key(base_key, login_id, client_id);
        self.set_cache_by_key(&cache_key, data, timeout).await
    }
    
    /// 通用设置缓存方法
    async fn set_cache_by_key<T: Serialize>(&self, cache_key: &str, data: T, timeout: u64) -> TokenResult<()> {
        let json_str = serde_json::to_string(&data)
            .map_err(|e| {
                log::warn!("序列化数据失败: {:?}", e.to_string());
                TokenError::PermissionNotFound(e.to_string())
            })?;
        Ok(self.storage
            .set(cache_key, &json_str, Some(std::time::Duration::from_secs(timeout)))
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?)
    }
    
    /// 通用获取缓存方法
    async fn get_cache<T: for<'de> Deserialize<'de> + Default>(&self, base_key: &str, login_id: &str, client_id: &str) -> TokenResult<T> {
        let cache_key = self.build_cache_key(base_key, login_id, client_id);
        self.get_cache_by_key::<T>(&cache_key).await
    }

    /// 通用获取缓存方法
    async fn get_cache_by_key<T: for<'de> Deserialize<'de> + Default>(&self, cache_key: &str) -> TokenResult<T> {
        // 1. 尝试从Redis获取缓存
        let json_str: Option<String> = self.storage.get(cache_key).await
            .map_err(|e| {
                log::warn!("Redis get error: {:?}, fetching from database", e.to_string());
                TokenError::PermissionNotFound(e.to_string())
            })
            .ok()
            .flatten();

        if let Some(json_str) = json_str {
            log::debug!("Got data from cache for user_id: {}", cache_key);
            // 解析JSON并返回
            let data: T = serde_json::from_str(&json_str)
                .map_err(|e| {
                    log::warn!("解析缓存失败: {:?}", e.to_string());
                    TokenError::PermissionNotFound(e.to_string())
                })?;
            return Ok(data);
        }
        Ok(T::default())
    }
    
    /// 通用清除缓存方法
    async fn clean_cache(&self, base_key: &str, login_id: &str, client_id: &str) -> TokenResult<()> {
        let cache_key = self.build_cache_key(base_key, login_id, client_id);
        self.clean_cache_by_key(&cache_key).await
    }

    /// 通用清除缓存方法
    async fn clean_cache_by_key(&self, cache_key: &str) -> TokenResult<()> {
        // 只有当缓存键存在时才执行删除操作
        if let Ok(Some(_)) = self.storage.get(&cache_key).await {
            Ok(self.storage
                .delete(&cache_key)
                .await
                .map_err(|e| TokenError::StorageError(e.to_string()))?)
        } else {
            // 如果键不存在，直接返回成功
            Ok(())
        }
    }
    
    // ==================== 公共方法 ====================
    
    /// 设置权限存储
    pub async fn set_permission<T: Serialize>(&self, login_id: &str, client_id: &str, permission_vec: T, timeout: u64) -> TokenResult<()> {
        let permission_key = self.config.cache_permission_key.clone().unwrap_or_default();
        self.set_cache::<T>(&permission_key, login_id, client_id, permission_vec, timeout).await
    }

    /// 获取权限
    pub async fn get_permission<T: for<'de> Deserialize<'de> + Default>(&self, login_id: &str, client_id: &str) -> TokenResult<T> {
        let permission_key = self.config.cache_permission_key.clone().unwrap_or_default();
        self.get_cache::<T>(&permission_key, login_id, client_id).await
    }
    
    /// 删除权限
    pub async fn clean_permission(&self, login_id: &str, client_id: &str) -> TokenResult<()> {
        let permission_key = self.config.cache_permission_key.clone().unwrap_or_default();
        self.clean_cache(&permission_key, login_id, client_id).await
    }

    /// 设置角色权限存储
    pub async fn set_role<T: Serialize>(&self, login_id: &str, client_id: &str, role_vec: T, timeout: u64) -> TokenResult<()> {
        let role_key = self.config.cache_role_key.clone().unwrap_or_default();
        self.set_cache::<T>(&role_key, login_id, client_id, role_vec, timeout).await
    }

    /// 获取角色
    pub async fn get_role<T: for<'de> Deserialize<'de> + Default>(&self, login_id: &str, client_id: &str) -> TokenResult<T> {
        let role_key = self.config.cache_role_key.clone().unwrap_or_default();
        self.get_cache::<T>(&role_key, login_id, client_id).await
    }

    /// 删除权限
    pub async fn clean_role(&self, login_id: &str, client_id: &str) -> TokenResult<()> {
        let role_key = self.config.cache_role_key.clone().unwrap_or_default();
        self.clean_cache(&role_key, login_id, client_id).await
    }

    /// 设置自定义缓存
    pub async fn set_custom_cache<T: Serialize>(&self, custom_key:&str, val:T, timeout: u64) -> TokenResult<()> {
        self.set_cache_by_key::<T>(custom_key, val, timeout).await
    }

    /// 清除自定义缓存
    pub async fn clean_custom_cache(&self, custom_key:&str) -> TokenResult<()> {
        self.clean_cache_by_key(custom_key).await
    }

    /// 获取自定义缓存
    pub async fn get_custom_cache<T: for<'de> Deserialize<'de> + Default>(&self, custom_key:&str) -> TokenResult<T> {
        self.get_cache_by_key::<T>(custom_key).await
    }
}
