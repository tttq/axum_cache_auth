use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use spring::config::Configurable;
use std::collections::HashSet;

spring::submit_config_schema!("auth", AuthConfig);

#[derive(Debug,Clone, Configurable, JsonSchema, Deserialize)]
#[config_prefix = "auth"]
pub struct AuthConfig {
    /// 是否启用认证
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_auth: Option<bool>,
    /// jwt 存储用户key
    pub info_name: String,
    /// 项目名称
    #[serde(default = "default_project_name")]
    pub project_name: Option<String>,
    /// token名称
    #[serde(default = "default_header_name")]
    pub header_name: Option<String>,
    /// token前缀
    #[serde(default = "default_header_prefix")]
    pub header_prefix: Option<String>,
    /// 权限key
    #[serde(default = "default_permission_key")]
    pub permission_key: Option<String>,
    /// 权限code
    #[serde(default = "default_permission_code")]
    pub header_permission_code: Option<String>,
    /// 角色key
    #[serde(default = "default_role_code")]
    pub header_role_code: Option<String>,
    /// token过期时间
    pub expire: u64,
    /// token样式
    pub style: TokenStyle,
    /// 存储类型
    pub storage: TokenStorage,
    /// token存储名称
    #[serde(default = "default_storage_name")]
    pub storage_name: Option<String>,
    /// cookie名称
    #[serde(default = "default_cookie_name")]
    pub cookie_name: Option<String>,
    /// 白名单路径
    pub whitelist_paths: HashSet<String>,

    /// jwt密钥
    pub jwt_secret_key: Option<String>,
    /// token算法
    pub jwt_algorithm: Option<String>,
    /// JWT 签发者
    pub jwt_issuer: Option<String>,
    /// JWT 受众
    pub jwt_audience: Option<String>,

    /// 是否启用 Refresh Token
    pub enable_refresh_token: bool,

    /// Refresh Token 有效期（秒），默认 7 天
    pub refresh_token_timeout: u64,

    /// 是否并发登录（默认允许）
    pub is_concurrent: bool,
    /// 自动续签（默认开启）
    pub auto_renew: bool,
    /// token存活时间(秒)
    pub active_timeout: u64

}
impl Default for AuthConfig {
    fn default() -> Self {
        let mut whitelist_paths = HashSet::new();
        whitelist_paths.insert("/api/system/auth/login".to_string());
        whitelist_paths.insert("/api/system/auth/register".to_string());
        whitelist_paths.insert("/api/system/auth/send-code".to_string());
        whitelist_paths.insert("/api/system/auth/captcha".to_string());
        whitelist_paths.insert("/api/system/auth/verify-captcha".to_string());
        whitelist_paths.insert("/health".to_string());
        whitelist_paths.insert("/docs".to_string());
        whitelist_paths.insert("/openapi.json".to_string());
        AuthConfig {
            is_auth: Some(true),
            info_name: "UserInfo".to_string(),
            project_name: default_project_name(),
            header_name: default_header_name(),
            header_prefix: default_header_prefix(),
            permission_key: default_permission_key(),
            header_permission_code: default_permission_code(),
            header_role_code: default_role_code(),
            expire: 3600,
            active_timeout: 3600,
            style: TokenStyle::Hash,
            storage: TokenStorage::All,
            storage_name: default_storage_name(),
            cookie_name: default_cookie_name(),
            whitelist_paths,
            jwt_secret_key: None,
            jwt_algorithm: Some("HS256".to_string()),
            jwt_issuer: None,
            jwt_audience: None,
            enable_refresh_token: false,
            refresh_token_timeout: 604800, // 7 天
            is_concurrent: true,
            auto_renew: true,
        }
    }
}
impl AuthConfig {
    pub fn timeout_duration(&self)-> Option<std::time::Duration>{
       Some( std::time::Duration::from_secs(self.expire))
    }

}

fn default_project_name() -> Option<String>{
    Some("pocket".to_string())
}
fn default_permission_key() -> Option<String>{
    Some(format!("{}:{}",default_project_name().unwrap(),"permission"))
}
fn default_header_prefix() -> Option<String>{
    Some("Bearer ".to_string())
}
fn default_header_name() -> Option<String>{
   Some("Authorization".to_string())
}
fn default_cookie_name() -> Option<String>{
   Some("pocket_cookie".to_string())
}
fn default_permission_code() -> Option<String>{
   Some("X-Permission-Code".to_string())
}
fn default_role_code() -> Option<String>{
   Some("X-Role-Code".to_string())
}

fn default_storage_name()-> Option<String>{
   Some( format!("{}:{}",default_project_name().unwrap(),"token"))
}

#[derive(Debug, Clone, JsonSchema, Deserialize)]
pub enum TokenStorage {
    Memory,
    Redis,
    All
}

/// Token 风格 | Token Style
#[derive(Debug, Clone, Copy, JsonSchema, Serialize, Deserialize)]
pub enum TokenStyle {
    /// UUID 风格 | UUID style
    Uuid,
    /// 简化的 UUID（去掉横杠）| Simple UUID (without hyphens)
    SimpleUuid,
    /// 32位随机字符串 | 32-character random string
    Random32,
    /// 64位随机字符串 | 64-character random string
    Random64,
    /// 128位随机字符串 | 128-character random string
    Random128,
    /// JWT 风格（JSON Web Token）| JWT style (JSON Web Token)
    Jwt,
    /// Hash 风格（SHA256哈希）| Hash style (SHA256 hash)
    Hash,
    /// 时间戳风格（毫秒级时间戳+随机数）| Timestamp style (millisecond timestamp + random)
    Timestamp,
    /// Tik 风格（短小精悍的8位字符）| Tik style (short 8-character token)
    Tik,
}