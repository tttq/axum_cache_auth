
//! StpUtil - sa-token 便捷工具类
//! 
//! 提供类似 Java 版 StpUtil 的静态方法，方便进行认证和权限操作
//! 
//! ## 使用示例
//! 
//! ```rust,ignore
//! use crate::auth::utils::StpUtil;
//! 
//! // 初始化全局 Manager（应用启动时调用一次）
//! StpUtil::init_manager(manager);
//! 
//! // 之后就可以直接使用，支持多种 ID 类型
//! let token = StpUtil::login("user_123").await?;  // 字符串 ID
//! let token = StpUtil::login(10001).await?;       // 数字 ID (i32)
//! let token = StpUtil::login(10001_i64).await?;   // 数字 ID (i64)
//! 
//! StpUtil::set_permissions(10001, vec!["user:list".to_string()]).await?;
//! ```

use std::fmt::Display;
use std::sync::Arc;
use once_cell::sync::OnceCell;

use crate::auth::error::{TokenError, TokenResult};
use crate::auth::manager::TokenManager;
use crate::auth::token::{TokenInfo, TokenValue};
use crate::auth::{TokenContextManager};
use crate::store::store_result::StorageTrait;

/// 全局 TokenManager 实例
static GLOBAL_MANAGER: OnceCell<Arc<TokenManager>> = OnceCell::new();

/// LoginId trait - 支持任何可以转换为字符串的类型作为登录 ID
/// 
/// 自动实现了 String, &str, i32, i64, u32, u64 等常用类型
pub trait LoginId {
    fn to_login_id(&self) -> String;
}

// 为所有实现了 Display 的类型自动实现 LoginId
impl<T: Display> LoginId for T {
    fn to_login_id(&self) -> String {
        self.to_string()
    }
}

/// StpUtil - 权限认证工具类
/// 
/// 提供便捷的认证和授权操作方法，类似于 Java 版 sa-token 的 StpUtil
pub struct StpUtil;

impl StpUtil {
    // ==================== 初始化 ====================
    
    /// 初始化全局 TokenManager（应用启动时调用一次）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// let manager = TokenManager::new(storage, config, auth_valid_trait);
    /// StpUtil::init_manager(Arc::new(manager));
    /// ```
    pub fn init_manager(manager: Arc<TokenManager>) {
        GLOBAL_MANAGER.set(manager)
            .unwrap_or_else(|_| panic!("StpUtil manager already initialized"));
    }
    
    /// 获取全局 Manager
    fn get_manager() -> &'static Arc<TokenManager> {
        GLOBAL_MANAGER.get()
            .expect("StpUtil not initialized. Call StpUtil::init_manager() first.")
    }
    
    // ==================== 登录相关 ====================
    
    /// 会话登录
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 支持字符串 ID
    /// let token = StpUtil::login("user_123").await?;
    /// 
    /// // 支持数字 ID
    /// let token = StpUtil::login(10001).await?;
    /// let token = StpUtil::login(10001_i64).await?;
    /// ```
    pub async fn login(login_id: impl LoginId) -> TokenResult<TokenValue> {
        Self::get_manager().login(login_id.to_login_id()).await
    }

    pub async fn login_with_type(login_id: impl LoginId, _login_type: impl Into<String>) -> TokenResult<TokenValue> {
        Self::get_manager().login(login_id.to_login_id()).await
    }
    
    /// 登录并设置额外数据 | Login with extra data
    /// 
    /// # 参数 | Arguments
    /// * `login_id` - 登录ID | Login ID
    /// * `extra_data` - 额外数据 | Extra data
    pub async fn login_with_extra(
        login_id: impl LoginId,
        extra_data: serde_json::Value,
    ) -> TokenResult<TokenValue> {
        let manager = Self::get_manager();
        let login_id = login_id.to_login_id();
        
        let token = manager.login_with_options(
            login_id,
            None,
            None,
            Some(extra_data),
            None,
            None
        ).await?;
        
        Ok(token)
    }
    
    /// 会话登出
    pub async fn logout(token: &TokenValue) -> TokenResult<()> {
        log::debug!("开始执行 logout，token: {}", token);
        let result = Self::get_manager().logout(token).await;
        match &result {
            Ok(_) => log::debug!("logout 执行成功，token: {}", token),
            Err(e) => log::debug!("logout 执行失败，token: {}, 错误: {}", token, e),
        }
        result
    }
    
    /// 踢人下线（根据登录ID）
    pub async fn kick_out(login_id: impl LoginId) -> TokenResult<()> {
        Self::get_manager().kick_out(&login_id.to_login_id()).await
    }
    
    /// 强制登出（根据登录ID）
    pub async fn logout_by_login_id(login_id: impl LoginId) -> TokenResult<()> {
        Self::get_manager().logout_by_login_id(&login_id.to_login_id()).await
    }
    
    /// 根据 token 登出（别名方法，更直观）
    pub async fn logout_by_token(token: &TokenValue) -> TokenResult<()> {
        Self::logout(token).await
    }
    
    // ==================== 当前会话操作（无参数，从上下文获取）====================
    
    /// 获取当前请求的 token（无参数，从上下文获取）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let token = StpUtil::get_token_value()?;
    /// ```
    pub fn get_token_value() -> TokenResult<TokenValue> {
        let ctx = TokenContextManager::get_current()
            .ok_or(TokenError::NotLogin)?;
        ctx.token.ok_or(TokenError::NotLogin)
    }
    
    /// 当前会话登出（无参数，从上下文获取 token）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// StpUtil::logout_current().await?;
    /// ```
    pub async fn logout_current() -> TokenResult<()> {
        let token = Self::get_token_value()?;
        log::debug!("成功获取 token: {}", token);
        
        let result = Self::logout(&token).await;
        match &result {
            Ok(_) => log::debug!("logout_current 执行成功，token: {}", token),
            Err(e) => log::debug!("logout_current 执行失败，token: {}, 错误: {}", token, e),
        }
        result
    }
    
    /// 检查当前会话是否登录（无参数，返回 bool）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// if StpUtil::is_login_current() {
    ///     println!("当前用户已登录");
    /// }
    /// ```
    pub fn is_login_current() -> bool {
        if let Ok(_token) = Self::get_token_value() {
            // 注意：这里使用同步检查，只检查上下文中是否有 token
            // 如果需要异步验证，需要使用 is_login(&token).await
            true
        } else {
            false
        }
    }
    
    /// 检查当前会话登录状态，未登录则抛出异常（无参数）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// StpUtil::check_login_current()?;
    /// ```
    pub fn check_login_current() -> TokenResult<()> {
        Self::get_token_value()?;
        Ok(())
    }
    
    /// 获取当前会话的 login_id（String 类型，无参数）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let login_id = StpUtil::get_login_id_as_string().await?;
    /// ```
    pub async fn get_login_id_as_string() -> TokenResult<String> {
        let ctx = TokenContextManager::get_current()
            .ok_or(TokenError::NotLogin)?;
        if let Some(login_id) = ctx.login_id {
            Ok(login_id)
        } else {
            let token = ctx.token.ok_or(TokenError::NotLogin)?;
            let token_info = Self::get_token_info(&token).await?;
            Ok(token_info.login_id)
        }
    }
    
    /// 获取当前会话的 login_id（i64 类型，无参数）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let user_id = StpUtil::get_login_id_as_long().await?;
    /// ```
    pub async fn get_login_id_as_long() -> TokenResult<i64> {
        let login_id_str = Self::get_login_id_as_string().await?;
        login_id_str.parse::<i64>()
            .map_err(|_| TokenError::LoginIdNotNumber)
    }
    
    /// 获取当前会话的 token 信息（无参数）
    /// 
    /// # 示例
    /// ```rust,ignore
    /// // 在请求处理函数中
    /// let token_info = StpUtil::get_token_info_current()?;
    /// println!("Token 创建时间: {:?}", token_info.create_time);
    /// ```
    pub fn get_token_info_current() -> TokenResult<Arc<TokenInfo>> {
        let ctx = TokenContextManager::get_current()
            .ok_or(TokenError::NotLogin)?;
        ctx.token_info.ok_or(TokenError::NotLogin)
    }
    
    // ==================== Token 验证 ====================
    
    /// 检查当前 token 是否已登录
    pub async fn is_login(token: &TokenValue) -> bool {
        Self::get_manager().is_valid(token).await
    }
    
    /// 根据登录 ID 检查是否已登录
    /// 
    /// # 示例
    /// ```rust,ignore
    /// let is_logged_in = StpUtil::is_login_by_login_id("user_123").await;
    /// let is_logged_in = StpUtil::is_login_by_login_id(10001).await;
    /// ```
    pub async fn is_login_by_login_id(login_id: impl LoginId) -> bool {
        match Self::get_token_by_login_id(login_id).await {
            Ok(token) => Self::is_login(&token).await,
            Err(_) => false,
        }
    }
    
    /// 检查当前 token 是否已登录，如果未登录则抛出异常
    pub async fn check_login(token: &TokenValue) -> TokenResult<()> {
        if !Self::is_login(token).await {
            return Err(TokenError::NotLogin);
        }
        Ok(())
    }
    
    /// 获取 token 信息
    pub async fn get_token_info(token: &TokenValue) -> TokenResult<TokenInfo> {
        Self::get_manager().get_token_info(token).await
    }
    
    /// 获取当前 token 的登录ID
    pub async fn get_login_id(token: &TokenValue) -> TokenResult<String> {
        let token_info = Self::get_manager().get_token_info(token).await?;
        Ok(token_info.login_id)
    }
    
    /// 获取当前 token 的登录ID，如果未登录则返回默认值
    pub async fn get_login_id_or_default(
        token: &TokenValue,
        default: impl Into<String>,
    ) -> String {
        Self::get_login_id(token)
            .await
            .unwrap_or_else(|_| default.into())
    }
    
    /// 根据登录 ID 获取当前用户的 token
    /// 
    /// # 示例
    /// ```rust,ignore
    /// let token = StpUtil::get_token_by_login_id("user_123").await?;
    /// let token = StpUtil::get_token_by_login_id(10001).await?;
    /// ```
    pub async fn get_token_by_login_id(login_id: impl LoginId) -> TokenResult<TokenValue> {
        let manager = Self::get_manager();
        let login_id_str = login_id.to_login_id();
        let config = &manager.config;
        
        // 从存储中获取该用户的 token
        let store_name = config.storage_name.clone().unwrap_or_default();
        let key = format!("{}:{}", store_name, login_id_str);
        match manager.storage.get(&key).await {
            Ok(Some(token_str)) => Ok(TokenValue::new(token_str)),
            Ok(None) => Err(TokenError::NotLogin),
            Err(e) => Err(TokenError::StorageError(e.to_string())),
        }
    }
    
    // ==================== Token 相关 ====================
    
    /// 创建一个新的 token（但不登录）
    pub fn create_token(token_value: impl Into<String>) -> TokenValue {
        TokenValue::new(token_value.into())
    }
    
    /// 检查 token 格式是否有效（仅检查格式，不检查是否存在于存储中）
    pub fn is_valid_token_format(token: &str) -> bool {
        !token.is_empty() && token.len() >= 16
    }
}

impl StpUtil {
    /// 批量踢人下线
    pub async fn kick_out_batch<T: LoginId>(
        login_ids: &[T],
    ) -> TokenResult<Vec<Result<(), TokenError>>> {
        let manager = Self::get_manager();
        let mut results = Vec::new();
        for login_id in login_ids {
            results.push(manager.kick_out(&login_id.to_login_id()).await);
        }
        Ok(results)
    }
    
    /// 获取 token 剩余有效时间（秒）
    pub async fn get_token_timeout(token: &TokenValue) -> TokenResult<Option<i64>> {
        let manager = Self::get_manager();
        let token_info = manager.get_token_info(token).await?;
        
        if let Some(expire_time) = token_info.expire_time {
            let now = chrono::Utc::now();
            let duration = expire_time.signed_duration_since(now);
            Ok(Some(duration.num_seconds()))
        } else {
            Ok(None) // 永久有效
        }
    }
    
    /// 续期 token（重置过期时间）
    pub async fn renew_timeout(
        token: &TokenValue,
        timeout_seconds: i64,
    ) -> TokenResult<()> {
        let manager = Self::get_manager();
        manager.renew_timeout(token, timeout_seconds).await
    }
    
    // ==================== 额外数据操作 | Extra Data Operations ====================
    
    /// 设置 Token 的额外数据 | Set extra data for token
    /// 
    /// # 参数 | Arguments
    /// * `token` - Token值 | Token value
    /// * `extra_data` - 额外数据 | Extra data
    pub async fn set_extra_data(
        token: &TokenValue,
        extra_data: serde_json::Value,
    ) -> TokenResult<()> {
        let manager = Self::get_manager();
        let mut token_info = manager.get_token_info(token).await?;
        token_info.extra_data = Some(extra_data);
        
        let store_name = manager.config.storage_name.clone().unwrap_or_default();
        let key = format!("{}:{}", store_name, token.as_str());
        let value = serde_json::to_string(&token_info)
            .map_err(|e| TokenError::SerializationError(e))?;
        
        manager.storage.set(&key, &value, manager.config.timeout_duration()).await
            .map_err(|e| TokenError::StorageError(e.to_string()))?;
        
        Ok(())
    }
    
    /// 获取 Token 的额外数据 | Get extra data from token
    /// 
    /// # 参数 | Arguments
    /// * `token` - Token值 | Token value
    pub async fn get_extra_data(token: &TokenValue) -> TokenResult<Option<serde_json::Value>> {
        let manager = Self::get_manager();
        let token_info = manager.get_token_info(token).await?;
        Ok(token_info.extra_data)
    }
    
    // ==================== 链式调用 | Chain Call ====================
    
    /// 创建 Token 构建器，用于链式调用 | Create token builder for chain calls
    /// 
    /// # 示例 | Example
    /// ```rust,ignore
    /// use serde_json::json;
    /// 
    /// // 链式调用示例
    /// let token = StpUtil::builder("user_123")
    ///     .extra_data(json!({"ip": "192.168.1.1"}))
    ///     .device("pc")
    ///     .login_type("admin")
    ///     .login()
    ///     .await?;
    /// ```
    pub fn builder(login_id: impl LoginId) -> TokenBuilder {
        TokenBuilder::new(login_id.to_login_id())
    }
}

/// Token 构建器 - 支持链式调用 | Token Builder - Supports chain calls
pub struct TokenBuilder {
    login_id: String,
    extra_data: Option<serde_json::Value>,
    device: Option<String>,
    login_type: Option<String>,
}

impl TokenBuilder {
    /// 创建新的 Token 构建器 | Create new token builder
    pub fn new(login_id: String) -> Self {
        Self {
            login_id,
            extra_data: None,
            device: None,
            login_type: None,
        }
    }
    
    /// 设置额外数据 | Set extra data
    pub fn extra_data(mut self, data: serde_json::Value) -> Self {
        self.extra_data = Some(data);
        self
    }
    
    /// 设置设备信息 | Set device info
    pub fn device(mut self, device: impl Into<String>) -> Self {
        self.device = Some(device.into());
        self
    }
    
    /// 设置登录类型 | Set login type
    pub fn login_type(mut self, login_type: impl Into<String>) -> Self {
        self.login_type = Some(login_type.into());
        self
    }
    
    /// 执行登录操作 | Execute login
    /// 
    /// 如果不提供 login_id 参数，则使用构建器中的 login_id
    pub async fn login<T: LoginId>(self, login_id: Option<T>) -> TokenResult<TokenValue> {
        let manager = StpUtil::get_manager();
        
        // 登录获取 token，使用传入的 login_id 或构建器中的 login_id
        let final_login_id = match login_id {
            Some(id) => id.to_login_id(),
            None => self.login_id,
        };
        
        let token = manager.login_with_options(
            final_login_id,
            self.login_type,
            self.device,
            self.extra_data,
            None,
            None
        ).await?;
        
        Ok(token)
    }
}