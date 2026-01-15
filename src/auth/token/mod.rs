//! Token 管理模块

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod generator;
pub mod jwt;
pub mod validator;

pub use jwt::{JwtAlgorithm, JwtClaims, JwtManager};

/// Token 值
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TokenValue(String);

impl TokenValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for TokenValue {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<TokenValue> for String {
    fn from(v: TokenValue) -> Self {
        v.0
    }
}

impl std::fmt::Display for TokenValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Token 信息 | Token Information
///
/// 存储 Token 的完整信息，包括元数据和安全特性
/// Stores complete token information, including metadata and security features
///
/// # 字段说明 | Field Description
/// - `token`: Token 值 | Token value
/// - `login_id`: 登录用户 ID | Logged-in user ID
/// - `login_type`: 登录类型（如 "user", "admin"）| Login type (e.g., "user", "admin")
/// - `create_time`: Token 创建时间 | Token creation time
/// - `last_active_time`: 最后活跃时间 | Last active time
/// - `expire_time`: 过期时间（None 表示永不过期）| Expiration time (None means never expires)
/// - `device`: 设备标识 | Device identifier
/// - `extra_data`: 额外数据 | Extra data
/// - `nonce`: 防重放攻击的一次性令牌 | One-time token for replay attack prevention
/// - `refresh_token`: 用于刷新的长期令牌 | Long-term token for refresh
/// - `refresh_token_expire_time`: Refresh Token 过期时间 | Refresh token expiration time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token 值 | Token value
    pub token: TokenValue,

    /// 登录 ID | Login ID
    pub login_id: String,

    /// 登录类型（user、admin 等）| Login type (user, admin, etc.)
    pub login_type: String,

    /// Token 创建时间 | Token creation time
    pub create_time: DateTime<Utc>,

    /// Token 最后活跃时间 | Token last active time
    pub last_active_time: DateTime<Utc>,

    /// Token 过期时间（None 表示永不过期）| Token expiration time (None means never expires)
    pub expire_time: Option<DateTime<Utc>>,

    /// 设备标识 | Device identifier
    pub device: Option<String>,

    /// 额外数据 | Extra data
    pub extra_data: Option<serde_json::Value>,

    /// Nonce（用于防重放攻击）| Nonce (for replay attack prevention)
    pub nonce: Option<String>,

    /// Refresh Token（用于刷新访问令牌）| Refresh Token (for refreshing access token)
    pub refresh_token: Option<String>,

    /// Refresh Token 过期时间 | Refresh Token expiration time
    pub refresh_token_expire_time: Option<DateTime<Utc>>,
    /// 客户端标识 | Client identifier
    #[serde(default = "default_id")]
    pub client_id: Option<String>,
    /// 租户标识 | Tenant identifier
    #[serde(default = "default_id")]
    pub tenant_id: Option<String>,
}

impl TokenInfo {
    pub fn new(token: TokenValue, login_id: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            token,
            login_id: login_id.into(),
            login_type: "default".to_string(),
            create_time: now,
            last_active_time: now,
            expire_time: None,
            device: None,
            extra_data: None,
            nonce: None,
            refresh_token: None,
            refresh_token_expire_time: None,
            client_id: default_id(),
            tenant_id: default_id(),
        }
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expire_time) = self.expire_time {
            Utc::now() > expire_time
        } else {
            false
        }
    }

    pub fn update_active_time(&mut self) {
        self.last_active_time = Utc::now();
    }
}

fn default_id() -> Option<String> {
    Some("*".to_string())
}

/// Token 签名
#[derive(Debug, Clone)]
pub struct TokenSign {
    pub value: String,
    pub device: Option<String>,
}
