//! Token 管理器 - sa-token 的核心入口

use crate::auth::auth_config::AuthConfig;
use crate::auth::error::{TokenError, TokenResult};
use crate::auth::layer::AuthValidTrait;
use crate::auth::token::generator::TokenGenerator;
use crate::auth::token::{TokenInfo, TokenValue};
use crate::store::hybrid_storage::HybridStorage;
use crate::store::store_result::StorageTrait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;

/// sa-token 管理器
#[derive(Clone)]
pub struct TokenManager {
    pub storage: Arc<HybridStorage>,
    pub auth_valid_trait:Arc<dyn AuthValidTrait>,
    pub config: Arc<AuthConfig>,
}

impl TokenManager {
    /// 创建新的管理器实例
    pub fn new(storage: Arc<HybridStorage>, config: Arc<AuthConfig>, auth_valid_trait:Arc<dyn AuthValidTrait>) -> Self {
        Self { storage, config ,auth_valid_trait}
    }
    /// 登录：为指定账号创建 token
    pub async fn login(&self, login_id: impl Into<String>) -> TokenResult<TokenValue> {
        self.login_with_options(login_id, None, None, None, None, None)
            .await
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
        let store_name = self.config.storage_name.clone().unwrap_or_default();
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
            self.logout_by_login_id(&login_id).await?;
        }
        Ok(token)
    }

    /// 登出：删除指定 token
    pub async fn logout(&self, token: &TokenValue) -> TokenResult<()> {
        log::debug!("Manager: 开始 logout，token: {}", token);
        // 先从存储获取 token 信息，用于触发事件（不调用 get_token_info 避免递归）
        let store_name = self.config.storage_name.clone().unwrap_or_default();
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
        // 删除 token
        log::debug!("Manager: 删除 token，key: {}", key);
        self.storage
            .delete(&key)
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;
        log::debug!("Manager: token 已从存储中删除");

        // 触发登出事件
        if let Some(info) = token_info.clone() {
            log::debug!(
                "Manager: 触发登出事件，login_id: {}, login_type: {}",
                info.login_id,
                info.login_type
            );

            // 如果有在线用户管理，通知用户下线
            /*if let Some(online_mgr) = &self.online_manager {
                log::debug!("Manager: 标记用户下线，login_id: {}", info.login_id);
                online_mgr
                    .mark_offline(&info.login_id, token.as_str())
                    .await;
            }*/
        }

        log::debug!("Manager: logout 完成，token: {}", token);
        Ok(())
    }

    /// 根据登录 ID 登出所有 token
    pub async fn logout_by_login_id(&self, login_id: &str) -> TokenResult<()> {
        let store_name = self.config.storage_name.clone().unwrap_or_default();
        // 获取所有 token 键的前缀
        let token_prefix = store_name;

        // 获取所有 token 键
        if let Ok(keys) = self.storage.keys(&format!("{}*", token_prefix)).await {
            // 遍历所有 token 键
            for key in keys {
                // 获取 token 值
                if let Ok(Some(token_info_str)) = self.storage.get(&key).await {
                    // 反序列化 token 信息
                    if let Ok(token_info) = serde_json::from_str::<TokenInfo>(&token_info_str) {
                        // 如果 login_id 匹配，则登出该 token
                        if token_info.login_id == login_id {
                            // 提取 token 字符串（从键中移除前缀）
                            let token_str = key[token_prefix.len()..].to_string();
                            let token = TokenValue::new(token_str);

                            // 调用登出方法（logout 方法内部会处理删除映射和在线用户管理）
                            let _ = self.logout(&token).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// 获取 token 信息
    pub async fn get_token_info(&self, token: &TokenValue) -> TokenResult<TokenInfo> {
        let store_name = self.config.storage_name.clone().unwrap_or_default();
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

            // 直接续签（不递归调用 get_token_info）
            let _ = self
                .renew_timeout_internal(token, renew_timeout as i64, &token_info)
                .await;
        }

        Ok(token_info)
    }

    /// 检查 token 是否有效
    pub async fn is_valid(&self, token: &TokenValue) -> bool {
        self.get_token_info(token).await.is_ok()
    }

    /// 续期 token（重置过期时间）
    pub async fn renew_timeout(&self, token: &TokenValue, timeout_seconds: i64) -> TokenResult<()> {
        let token_info = self.get_token_info(token).await?;
        self.renew_timeout_internal(token, timeout_seconds, &token_info)
            .await
    }

    /// 内部续期方法（避免递归调用 get_token_info）
    async fn renew_timeout_internal(
        &self,
        token: &TokenValue,
        timeout_seconds: i64,
        token_info: &TokenInfo,
    ) -> TokenResult<()> {
        let mut new_token_info = token_info.clone();

        // 设置新的过期时间
        use chrono::{Duration, Utc};
        let new_expire_time = Utc::now() + Duration::seconds(timeout_seconds);
        new_token_info.expire_time = Some(new_expire_time);
        let store_name = self.config.storage_name.clone().unwrap_or_default();
        // 保存更新后的 token 信息
        let key = format!("{}:{}",store_name, token.as_str());
        let value = serde_json::to_string(&new_token_info)
            .map_err(|e| TokenError::SerializationError(e))?;

        let timeout = std::time::Duration::from_secs(timeout_seconds as u64);
        self.storage
            .set(&key, &value, Some(timeout))
            .await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// 踢人下线
    pub async fn kick_out(&self, login_id: &str) -> TokenResult<()> {
        let _token_result = self
            .storage
            .get(&format!("sa:login:token:{}", login_id))
            .await;


        self.logout_by_login_id(login_id).await?;

        Ok(())
    }
}
