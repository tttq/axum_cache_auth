pub mod utils;
pub mod adapter;
pub mod auth_config;
pub mod context;
pub mod error;
pub mod extractor;
pub mod layer;
pub mod manager;
pub mod token;


use crate::auth::token::{TokenInfo, TokenValue};
use std::cell::RefCell;
use std::sync::Arc;
use tokio::task_local;

// 使用 tokio::task_local 存储当前请求的上下文
// 设为 private，外部只能通过 TokenContextManager 访问
task_local! {
    // 注意：tokio::task_local! 宏只定义变量，不支持直接初始化
    static CURRENT_CONTEXT: RefCell<Option<TokenContext>>;
}
#[derive(Debug, Clone)]
pub struct TokenContext {
    /// 当前请求的 token | Current request's token
    pub token: Option<TokenValue>,

    /// 当前请求的 token 信息 | Current request's token info
    pub token_info: Option<Arc<TokenInfo>>,

    /// 登录 ID | Login ID
    pub login_id: Option<String>,
}
impl TokenContext{
    pub fn new() -> Self {
        Self {
            token: None,
            token_info: None,
            login_id: None,
        }
    }
    pub fn new_with_token(token: TokenValue,token_info: TokenInfo,login_id: String) -> Self {
        Self {
            token: Some(token),
            token_info: Some(Arc::new(token_info)),
            login_id: Some(login_id),
        }
    }
}
/// Token 上下文管理工具，用于在请求处理过程中设置和获取上下文
pub struct TokenContextManager;

impl TokenContextManager {
    /// 使用 scope 方法包装请求处理，确保上下文在请求结束时自动清除
    pub async fn scope<F, Fut>(context: TokenContext, f: F) -> Fut::Output
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future,
    {
        // 使用 scope 方法初始化 tokio::task_local 变量，并在任务完成后自动清除
        CURRENT_CONTEXT
            .scope(RefCell::new(Some(context)), async move { f().await })
            .await
    }
    /// 设置当前请求的上下文
    pub fn set_context(context: TokenContext) {
        // 使用 try_with 方法，避免在上下文未初始化时panic
        let _ = CURRENT_CONTEXT.try_with(|cell| {
            *cell.borrow_mut() = Some(context);
        });
    }


    /// 获取当前请求的上下文
    pub fn get_current() -> Option<TokenContext> {
        // 使用 try_with 方法，避免在上下文未初始化时panic
        CURRENT_CONTEXT
            .try_with(|cell| cell.borrow().clone())
            .unwrap_or(None)
    }

    /// 清除当前上下文 | Clear Current Context
    ///
    /// 清除当前线程的上下文信息
    /// Clear current thread's context information
    pub fn clear() {
        CURRENT_CONTEXT.with(|c| {
            *c.borrow_mut() = None;
        });
    }
}