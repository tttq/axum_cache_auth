//! Axum中间件层

use crate::auth::adapter::AxumRequestAdapter;
use crate::auth::auth_config::AuthConfig;
use crate::auth::context::AxumRequest;
use crate::auth::error::messages;
use crate::auth::manager::TokenManager;
use crate::auth::token::TokenValue;
use crate::auth::utils::{TokenContext, TokenContextManager};
use crate::store::hybrid_storage::HybridStorage;
use crate::store::store_result::StorageTrait;
use async_trait::async_trait;
use http::{Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use spring_web::axum::response::IntoResponse;
use spring_web::axum::Json;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower::{Layer, Service};

#[async_trait]
pub trait AuthValidTrait: Send + Sync {
    /// 验证用户是否拥有指定权限
   async fn has_permission(&self,manager: Arc<TokenManager>, path:String, permission_code: Option<String>,key: Option<String>)->bool;
    /// 验证用户是否拥有指定角色
    async fn has_role(&self,manager: Arc<TokenManager>, path:String, role_code: Option<String>, role_key: Option<String>)->bool;
}

/// Axum应用状态
#[derive(Clone)]
pub struct TokenState {
    pub manager: Arc<TokenManager>,
}

impl TokenState {
    /// 从存储和配置创建状态
    pub fn new(storage: Arc<HybridStorage>, config: Arc<AuthConfig>, auth_valid_trait:Arc<dyn AuthValidTrait>) -> Self {
        Self {
            manager: Arc::new(TokenManager::new(storage, config,auth_valid_trait)),
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
        TokenMiddleware {
            inner,
            manager: self.state.manager.clone(),
            auth_valid_trait: self.state.manager.auth_valid_trait.clone(),
            whitelist_paths:  self.state.manager.config.whitelist_paths.iter().map(|s| s.as_str()).collect(),
            is_auth: self.state.manager.config.is_auth.unwrap_or_else(|| true),
            header_name: self.state.manager.config.header_name.unwrap_or_default(),
            header_prefix: self.state.manager.config.header_prefix.unwrap_or_default(),
            cookie_name: self.state.manager.config.cookie_name.unwrap_or_default(),
            header_permission_code: self.state.manager.config.header_permission_code.unwrap_or_default(),
            header_role_code: self.state.manager.config.header_role_code.unwrap_or_default(),
        }
    }
}


#[derive(Clone)]
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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for TokenMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let manager = self.manager.clone();
        let whitelist_paths = self.whitelist_paths.clone();
        let is_auth = self.is_auth.clone();
        Box::pin(async move {
            // 是否需要认证
            if !is_auth {
                return inner.call(request).await;
            }
            let path = request.uri().path();
            // 是否白名单路径
           let is_white_path= check_path(&whitelist_paths,path);
            if is_white_path {
                return inner.call(request).await;
            }
            // 获取权限编码（如果有）
            let permission_code = request.headers()
                .get(self.header_permission_code)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());

            // 获取权限编码（如果有）
            let role_code = request.headers()
                .get(self.header_role_code)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string());


            let token_str = extract_token_from_request(&request, &self.manager);
            if let Some(token_val) = token_str{
                let token = token_val.map(TokenValue::new);
                let (is_valid, token_info) = if let Some(ref t) = token {
                    let valid = manager.is_valid(t).await;
                    let info = if valid {
                        manager.get_token_info(t).await.ok()
                    } else {
                        None
                    };
                    (valid, info)
                } else {
                    (false, None)
                };
                // 认证失败
                if !is_valid {
                    return create_unauthorized_response()
                }
                let mut is_role_valid = false;
                let user_client_key = format!(":{}:{:?}",token_info.unwrap().login_id,token_info.unwrap().client_id);
                // 验证用户是否拥有指定角色
                if self.auth_valid_trait.has_role(self.manager,path.to_string(), role_code,user_client_key){
                    is_role_valid = true;
                }
                // 验证用户是否拥有指定权限
                if !self.auth_valid_trait.has_permission(self.manager,path.to_string(), permission_code,user_client_key) && !is_role_valid{
                    return create_forbidden_response()
                }
              let context =  TokenContext::new_with_token(token, token_info,token_info.unwrap().login_id);
                // 使用 TokenContextManager::scope 包装后续请求处理
                return TokenContextManager::scope(context, move || async move {
                    let response=    inner.call(request).await;
                    TokenContextManager::clear();
                    response
                }).await;
            }
            return create_unauthorized_response();
        })
    }
}


/// 创建未授权响应
fn create_unauthorized_response() -> Result<spring_web::axum::response::Response, StatusCode> {
    spring::tracing::log::debug!("Authentication failed, no valid token found");
    Ok((
        StatusCode::UNAUTHORIZED,
        Json(
            &json!({
                "code": 401,
                "message": messages::INVALID_TOKEN
            })),
    ).into_response())
}

/// 创建无权限响应
fn create_forbidden_response() -> Result<spring_web::axum::response::Response, StatusCode> {
    spring::tracing::log::debug!("Permission check failed");
    Ok(
        (
        StatusCode::FORBIDDEN,
        Json( &json!({
                "code": 403,
                "message": messages::PERMISSION_REQUIRED
            })),
    ).into_response())
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
pub fn extract_token_from_request<T>(request: &Request<T>, manager: &TokenManager) -> Option<String> {
    let adapter = AxumRequestAdapter::new(request);
    // 从配置中获取 token_name
    let token_name = &manager.config.header_name.unwrap_or_default();
    let cookie_name = &manager.config.cookie_name.unwrap_or_default();

    // 1. 优先从 Header 中获取（检查 token_name 配置的头）
    if let Some(token) = adapter.get_header(token_name) {
        return Some(extract_bearer_token(&token));
    }

    // 2. 如果 token_name 不是 "Authorization"，也尝试从 "Authorization" 头获取
    if token_name != "Authorization" {
        if let Some(token) = adapter.get_header("Authorization") {
            return Some(extract_bearer_token(&token));
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



/// Check if a path requires authentication 检查路径是否需要鉴权
pub fn check_path(whitelist_paths: &Vec<String>, path: &str) -> bool {
    // 白名单-请求排除列表
    need_auth(path, &whitelist_paths)
}

/// 提取 Bearer Token
///
/// 支持两种格式：
/// - `Bearer <token>` - 标准 Bearer Token 格式
/// - `<token>` - 直接的 Token 字符串
fn extract_bearer_token(header_value: &str) -> String {
    const BEARER_PREFIX: &str = "Bearer ";

    if header_value.starts_with(BEARER_PREFIX) {
        // 去除 "Bearer " 前缀
        header_value[BEARER_PREFIX.len()..].trim().to_string()
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