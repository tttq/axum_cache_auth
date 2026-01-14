//! 中间件实现
//!
//! 提供两种中间件：
//! - `TokenMiddleware`：基础中间件，从请求中提取token并设置上下文
//! - `AxumCheckLoginMiddleware`：检查登录中间件，未登录时返回401错误

use crate::auth::error::messages;
use http::{Request, Response, StatusCode};
use http_body;
use serde_json::json;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// 检查登录中间件层
#[derive(Clone)]
pub struct AxumCheckLoginLayer;

impl AxumCheckLoginLayer {
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for AxumCheckLoginLayer {
    type Service = AxumCheckLoginMiddleware<S>;
    
    fn layer(&self, inner: S) -> Self::Service {
        AxumCheckLoginMiddleware { inner }
    }
}

/// 检查登录中间件
/// 
/// 如果请求未登录，直接返回401错误
#[derive(Clone)]
pub struct AxumCheckLoginMiddleware<S> {
    inner: S,
}

/// 检查权限中间件层
#[derive(Clone)]
pub struct AxumCheckPermissionLayer {
    permission: String,
}

impl AxumCheckPermissionLayer {
    pub fn new(permission: impl Into<String>) -> Self {
        Self {
            permission: permission.into(),
        }
    }
}

impl<S> Layer<S> for AxumCheckPermissionLayer {
    type Service = AxumCheckPermissionMiddleware<S>;
    
    fn layer(&self, inner: S) -> Self::Service {
        AxumCheckPermissionMiddleware { 
            inner,
            permission: self.permission.clone(),
        }
    }
}

/// 检查权限中间件
/// 
/// 如果请求没有指定权限，直接返回403错误
#[derive(Clone)]
pub struct AxumCheckPermissionMiddleware<S> {
    inner: S,
    permission: String,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AxumCheckLoginMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    
    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        
        Box::pin(async move {
            // 检查是否有登录ID
            if request.extensions().get::<String>().is_none() {
                // 未登录，返回401错误
                // 由于我们无法直接返回AxumResponse，这里使用一个hack方法
                // 创建一个错误响应
                let mut response = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(ResBody::default())
                    .expect("Unable to create response");
                
                // 添加错误信息
                let error_json = serde_json::to_string(&json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                })).unwrap_or_default();
                
                return Ok(response);
            }
            
            // 已登录，继续处理
            inner.call(request).await
        })
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AxumCheckPermissionMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: http_body::Body + Default + Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    
    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let mut inner = self.inner.clone();
        let permission = self.permission.clone();
        
        Box::pin(async move {
            // 检查是否有登录ID
            if let Some(login_id) = request.extensions().get::<String>() {
                // 检查权限
                /*if sa_token_core::StpUtil::has_permission(login_id, &permission).await {
                    // 有权限，继续处理
                    return inner.call(request).await;
                }*/
            }
            
            // 无权限或未登录，返回403错误
            let mut response = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(ResBody::default())
                .expect("Unable to create response");
            
            // 添加错误信息
            let error_json = serde_json::to_string(&json!({
                "code": 403,
                "message": messages::PERMISSION_REQUIRED
            })).unwrap_or_default();
            
            // 添加到响应头中，这样上层可以读取
            if let Ok(header_value) = http::header::HeaderValue::from_str(&error_json) {
                response.headers_mut().insert("X-Permission-Token-Error", header_value);
            }
            
            Ok(response)
        })
    }
}
