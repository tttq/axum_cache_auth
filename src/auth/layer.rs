//! Axum中间件层

use crate::auth::adapter::AxumRequestAdapter;
use crate::auth::auth_config::AuthConfig;
use crate::auth::context::AxumRequest;
use crate::auth::error::messages;
use crate::auth::manager::TokenManager;
use crate::auth::token::TokenValue;
use crate::auth::{TokenContext, TokenContextManager};
use crate::store::hybrid_storage::HybridStorage;
use crate::CustomTimeoutTrait;
use async_trait::async_trait;
use http::{Request, Response, StatusCode};
use serde_json::json;
use spring_web::axum::body::Body;
use spring_web::axum::response::IntoResponse;
use spring_web::axum::Json;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[async_trait]
pub trait AuthValidTrait: Send + Sync {
    /// 验证用户是否拥有指定权限
   async fn has_permission(&self, manager: Arc<TokenManager>, path:String, permission_code: Option<String>,key: Option<String>)->bool;
    /// 验证用户是否拥有指定角色
    async fn has_role(&self, manager: Arc<TokenManager>, path:String, role_code: Option<String>, role_key: Option<String>)->bool;
}

/// Axum应用状态
#[derive(Clone)]
pub struct TokenState {
    pub manager: Arc<TokenManager>,
}

impl TokenState {
    /// 从存储和配置创建状态
    pub fn new(storage: Arc<HybridStorage>, config: Arc<AuthConfig>, auth_valid_trait:Arc<dyn AuthValidTrait>, custom_timeout_trait:Option<Arc<dyn CustomTimeoutTrait>>) -> Self {
        Self {
            manager: Arc::new(TokenManager::new(storage, config,auth_valid_trait,custom_timeout_trait)),
        }
    }

    /// 从 SaTokenManager 创建状态
    pub fn from_manager(manager: TokenManager) -> Self {
        Self {
            manager: Arc::new(manager),
        }
    }
}


/// Token layer for Axum with optional path-based authentication
/// 支持可选路径鉴权的 Axum Sa-Token 层
#[derive(Clone)]
pub struct TokenLayer {
    state: TokenState,

}

impl TokenLayer {
    pub fn new(state: TokenState) -> Self {
        Self { state}
    }

}

impl<S> Layer<S> for TokenLayer {
    type Service = TokenMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let manager = self.state.manager.clone();
        let config = &manager.config;
        
        TokenMiddleware {
            inner,
            manager: manager.clone(),
            auth_valid_trait: manager.auth_valid_trait.clone(),
            whitelist_paths: config.whitelist_paths.iter().cloned().collect(),
            is_auth: *config.is_auth.as_ref().unwrap_or(&true),
            header_name: config.header_name.as_ref().unwrap_or(&String::new()).clone(),
            header_prefix: config.header_prefix.as_ref().unwrap_or(&String::new()).clone(),
            cookie_name: config.cookie_name.as_ref().unwrap_or(&String::new()).clone(),
            header_permission_code: config.header_permission_code.as_ref().unwrap_or(&String::new()).clone(),
            header_role_code: config.header_role_code.as_ref().unwrap_or(&String::new()).clone(),
        }
    }
}


#[derive(Clone)]
#[allow(dead_code)]
pub struct TokenMiddleware<S> {
    pub(crate) inner: S,
    pub(crate) manager: Arc<TokenManager>,
    /// 鉴权组件
    pub(crate) auth_valid_trait:Arc<dyn AuthValidTrait>,
    /// Optional path authentication configuration
    /// 可选的路径鉴权配置
    pub(crate) whitelist_paths: Vec<String>,
    /// 是否开启认证
    pub(crate) is_auth: bool,
    /// 认证头名称
    pub(crate) header_name: String,
    /// 认证头前缀
    pub(crate) header_prefix: String,
    /// Cookie 名称
    pub(crate) cookie_name: String,
    /// 头权限编码
    pub(crate) header_permission_code: String,
    /// 头角色编码
    pub(crate) header_role_code: String,

}

impl<S, ReqBody> Service<Request<ReqBody>> for TokenMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        // 克隆整个中间件，避免生命周期问题
        let clone = self.clone();
        let mut inner = clone.inner;
        let manager = clone.manager;
        let auth_valid_trait = clone.auth_valid_trait;
        let whitelist_paths = clone.whitelist_paths;
        let is_auth = clone.is_auth;
        let header_permission_code = clone.header_permission_code;
        let header_role_code = clone.header_role_code;
        let header_name = clone.header_name;
        let header_prefix = clone.header_prefix;
        let cookie_name = clone.cookie_name;
        
        Box::pin(async move {
            let path = request.uri().path();
            // 是否需要认证检查
            let need_auth_check = is_auth && !check_path(&whitelist_paths, path);
            
            // 提取token（无论是否需要认证，都尝试提取）
            let token_str = extract_token_from_request(
                &request, 
                header_name.as_str(),
                cookie_name.as_str(),
                header_prefix.as_str()
            );
            
            // 处理token（如果有）
            if let Some(token_val) = token_str {
                let token_value = TokenValue::new(token_val);
                let valid = manager.is_valid(&token_value).await;
                let token_info = if valid {
                    manager.get_token_info(&token_value).await.ok()
                } else {
                    None
                };
                
                // 如果需要认证检查
                if need_auth_check {
                    // 认证失败
                    if !valid {
                        return Ok(create_unauthorized_response());
                    }
                    let config = manager.config.clone();
                    let token_info = token_info.unwrap();
                    let permission_key=config.cache_permission_key.clone().unwrap_or_default();
                    let role_key=config.cache_role_key.clone().unwrap_or_default();
                    
                    // 优化：只在client_id存在时才拼接，避免双引号
                    let user_permission_key = if let Some(client_id) = &token_info.client_id {
                        format!("{}:{}:{}", permission_key, &token_info.login_id, client_id)
                    } else {
                        format!("{}:{}", permission_key, &token_info.login_id)
                    };
                    
                    let user_role_key = if let Some(client_id) = &token_info.client_id {
                        format!("{}:{}:{}", role_key, &token_info.login_id, client_id)
                    } else {
                        format!("{}:{}", role_key, &token_info.login_id)
                    };
                    
                    // 获取权限编码（如果有）
                    let permission_code = request.headers()
                        .get(&header_permission_code)
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string());
                    
                    // 获取角色编码（如果有）
                    let role_code = request.headers()
                        .get(&header_role_code)
                        .and_then(|h| h.to_str().ok())
                        .map(|s| s.to_string());
                    
                    let is_role_valid = auth_valid_trait.has_role(
                        manager.clone(),
                        path.to_string(),
                        role_code.clone(),
                        Some(user_role_key.clone())
                    ).await;
                    
                    let has_permission = auth_valid_trait.has_permission(
                        manager.clone(),
                        path.to_string(),
                        permission_code.clone(),
                        Some(user_permission_key)
                    ).await;
                    
                    // 只有当既没有角色权限也没有功能权限时，才返回无权限响应
                    if !is_role_valid && !has_permission {
                        return Ok(create_forbidden_response());
                    }
                    
                    // 创建上下文并调用内部服务
                    let context = TokenContext::new_with_client_token(
                        token_value, 
                        token_info.clone(),
                        token_info.login_id.clone(),
                        token_info.client_id.unwrap_or_default().clone(),
                        token_info.tenant_id.unwrap_or_default().clone()
                    );
                    // 使用 TokenContextManager::scope 包装后续请求处理
                    return TokenContextManager::scope(context, move || async move {
                        let response = inner.call(request).await;
                        TokenContextManager::clear();
                        response
                    }).await;
                } else {
                    // 不需要认证检查，但有有效的token，写入上下文
                    if let Some(token_info) = token_info {
                        let context = TokenContext::new_with_client_token(
                            token_value, 
                            token_info.clone(),
                            token_info.login_id.clone(),
                            token_info.client_id.unwrap_or_default().clone(),
                            token_info.tenant_id.unwrap_or_default().clone()
                        );
                        // 使用 TokenContextManager::scope 包装后续请求处理
                        return TokenContextManager::scope(context, move || async move {
                            let response = inner.call(request).await;
                            TokenContextManager::clear();
                            response
                        }).await;
                    }
                    // 如果token无效或没有token_info，直接调用内部服务
                    return inner.call(request).await;
                }
            } else {
                // 没有token
                if need_auth_check {
                    // 需要认证但没有token，返回未授权
                    return Ok(create_unauthorized_response());
                } else {
                    // 不需要认证，直接调用内部服务
                    return inner.call(request).await;
                }
            }
        })
    }
}


/// 创建未授权响应
fn create_unauthorized_response() -> spring_web::axum::response::Response {
    spring::tracing::log::debug!("Authentication failed, no valid token found");
    (
        StatusCode::UNAUTHORIZED,
        Json(
            &json!({
                "code": 401,
                "message": messages::INVALID_TOKEN
            })),
    ).into_response()
}

/// 创建无权限响应
fn create_forbidden_response() -> spring_web::axum::response::Response {
    spring::tracing::log::debug!("Permission check failed");
    (
        StatusCode::FORBIDDEN,
        Json( &json!({
                "code": 403,
                "message": messages::PERMISSION_REQUIRED
            })),
    ).into_response()
}
/// 从请求中提取 Token
///
/// 按优先级顺序查找 Token：
/// 1. HTTP Header - `<token_name>: <token>` 或 `<token_name>: Bearer <token>`
/// 2. HTTP Header - `Authorization: <token>` 或 `Authorization: Bearer <token>`（标准头）
/// 3. Cookie - `<token_name>=<token>`
/// 4. Query Parameter - `?<token_name>=<token>`
///
/// # 参数
/// - `request` - HTTP 请求
/// - `state` - SaToken 状态（从配置中获取 token_name）
///
/// # 返回
/// - `Some(token)` - 找到有效的 token
/// - `None` - 未找到 token
pub fn extract_token_from_request<T>(request: &Request<T>, token_name: &str,cookie_name: &str,header_prefix: &str) -> Option<String> {
    let adapter = AxumRequestAdapter::new(request);

    // 1. 优先从 Header 中获取（检查 token_name 配置的头）
    if let Some(token) = adapter.get_header(token_name) {
        return Some(extract_bearer_token(&token,header_prefix));
    }

    // 2. 如果 token_name 不是 "Authorization"，也尝试从 "Authorization" 头获取
    if token_name != "Authorization" {
        if let Some(token) = adapter.get_header("Authorization") {
            return Some(extract_bearer_token(&token,header_prefix));
        }
    }

    // 3. 从 Cookie 中获取
    if let Some(token) = adapter.get_cookie(cookie_name) {
        return Some(token);
    }

    // 4. 从 Query 参数中获取
    if let Some(query) = request.uri().query() {
        if let Some(token) = parse_query_param(query, token_name) {
            return Some(token);
        }
    }

    None
}



/// Check if a path is in the whitelist 检查路径是否在白名单中
pub fn check_path(whitelist_paths: &Vec<String>, path: &str) -> bool {
    // 白名单-请求排除列表
    match_any(path, whitelist_paths)
}

/// 提取 Bearer Token
///
/// 支持两种格式：
/// - `Bearer <token>` - 标准 Bearer Token 格式
/// - `<token>` - 直接的 Token 字符串
fn extract_bearer_token(header_value: &str,header_prefix: &str) -> String {
    if header_value.starts_with(header_prefix) {
        // 去除 "Bearer " 前缀
        header_value[header_prefix.len()..].trim().to_string()
    } else {
        // 直接返回 token
        header_value.trim().to_string()
    }
}


fn parse_query_param(query: &str, param_name: &str) -> Option<String> {
    for pair in query.split('&') {
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() == 2 && parts[0] == param_name {
            return urlencoding::decode(parts[1])
                .ok()
                .map(|s| s.into_owned());
        }
    }
    None
}


/// Check if path matches any pattern in the list
/// 检查路径是否匹配列表中的任意模式
pub fn match_any(path: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| match_path(path, p))
}

/// Determine if authentication is needed for a path
/// 判断路径是否需要鉴权
///
/// Returns `true` if path does not match any exclude patterns
/// 如果路径不匹配任何排除模式，返回 `true`（即需要认证）
pub fn need_auth(path: &str, exclude: &[String]) -> bool {
    !match_any(path, exclude)
}

pub fn match_path(path: &str, pattern: &str) -> bool {
    if pattern == "/**" {
        return true;
    }
    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return path.starts_with(prefix);
    }
    if pattern.starts_with("*") {
        let suffix = &pattern[1..];
        return path.ends_with(suffix);
    }
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        if path.starts_with(prefix) {
            let suffix = &path[prefix.len()..];
            return !suffix.contains('/') || suffix == "/";
        }
        return false;
    }
    path == pattern
}