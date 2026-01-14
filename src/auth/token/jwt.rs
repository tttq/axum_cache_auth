use crate::auth::error::{TokenError, TokenResult};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// JWT Algorithm | JWT 算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    /// HMAC using SHA-256 | 使用 SHA-256 的 HMAC
    HS256,
    /// HMAC using SHA-384 | 使用 SHA-384 的 HMAC
    HS384,
    /// HMAC using SHA-512 | 使用 SHA-512 的 HMAC
    HS512,
    /// RSA using SHA-256 | 使用 SHA-256 的 RSA
    RS256,
    /// RSA using SHA-384 | 使用 SHA-384 的 RSA
    RS384,
    /// RSA using SHA-512 | 使用 SHA-512 的 RSA
    RS512,
    /// ECDSA using SHA-256 | 使用 SHA-256 的 ECDSA
    ES256,
    /// ECDSA using SHA-384 | 使用 SHA-384 的 ECDSA
    ES384,
}

impl Default for JwtAlgorithm {
    fn default() -> Self {
        Self::HS256
    }
}

impl From<JwtAlgorithm> for Algorithm {
    fn from(alg: JwtAlgorithm) -> Self {
        match alg {
            JwtAlgorithm::HS256 => Algorithm::HS256,
            JwtAlgorithm::HS384 => Algorithm::HS384,
            JwtAlgorithm::HS512 => Algorithm::HS512,
            JwtAlgorithm::RS256 => Algorithm::RS256,
            JwtAlgorithm::RS384 => Algorithm::RS384,
            JwtAlgorithm::RS512 => Algorithm::RS512,
            JwtAlgorithm::ES256 => Algorithm::ES256,
            JwtAlgorithm::ES384 => Algorithm::ES384,
        }
    }
}

/// JWT Claims | JWT 声明
///
/// Standard JWT claims with sa-token extensions
/// 标准 JWT 声明及 sa-token 扩展
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user identifier) | 主题（用户标识符）
    #[serde(rename = "sub")]
    pub login_id: String,

    /// Issuer | 签发者
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Audience | 受众
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Expiration time (Unix timestamp) | 过期时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Not before time (Unix timestamp) | 生效时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Issued at time (Unix timestamp) | 签发时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// JWT ID (unique identifier) | JWT ID（唯一标识符）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    // Sa-token extensions | Sa-token 扩展字段

    /// Login type (user, admin, etc.) | 登录类型（用户、管理员等）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub login_type: Option<String>,

    /// Device identifier | 设备标识
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,

    /// Custom data | 自定义数据
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl JwtClaims {
    /// Create new JWT claims | 创建新的 JWT 声明
    ///
    /// # Arguments | 参数
    ///
    /// * `login_id` - User identifier | 用户标识符
    pub fn new(login_id: impl Into<String>) -> Self {
        let now = Utc::now().timestamp();
        Self {
            login_id: login_id.into(),
            iss: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: Some(now),
            jti: None,
            login_type: Some("default".to_string()),
            device: None,
            extra: HashMap::new(),
        }
    }

    /// Set expiration time in seconds from now | 设置从现在开始的过期时间（秒）
    ///
    /// # Arguments | 参数
    ///
    /// * `seconds` - Seconds until expiration | 到期秒数
    pub fn set_expiration(&mut self, seconds: i64) -> &mut Self {
        let exp_time = Utc::now() + Duration::seconds(seconds);
        self.exp = Some(exp_time.timestamp());
        self
    }

    /// Set expiration at specific time | 设置具体的过期时间
    pub fn set_expiration_at(&mut self, datetime: DateTime<Utc>) -> &mut Self {
        self.exp = Some(datetime.timestamp());
        self
    }

    /// Set issuer | 设置签发者
    pub fn set_issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.iss = Some(issuer.into());
        self
    }

    /// Set audience | 设置受众
    pub fn set_audience(&mut self, audience: impl Into<String>) -> &mut Self {
        self.aud = Some(audience.into());
        self
    }

    /// Set JWT ID | 设置 JWT ID
    pub fn set_jti(&mut self, jti: impl Into<String>) -> &mut Self {
        self.jti = Some(jti.into());
        self
    }

    /// Set login type | 设置登录类型
    pub fn set_login_type(&mut self, login_type: impl Into<String>) -> &mut Self {
        self.login_type = Some(login_type.into());
        self
    }

    /// Set device identifier | 设置设备标识
    pub fn set_device(&mut self, device: impl Into<String>) -> &mut Self {
        self.device = Some(device.into());
        self
    }

    /// Add custom claim | 添加自定义声明
    pub fn add_claim(&mut self, key: impl Into<String>, value: Value) -> &mut Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Get custom claim | 获取自定义声明
    pub fn get_claim(&self, key: &str) -> Option<&Value> {
        self.extra.get(key)
    }

    /// Set all custom claims at once | 一次设置所有自定义声明
    pub fn set_claims(&mut self, claims: HashMap<String, Value>) -> &mut Self {
        self.extra = claims;
        self
    }

    /// Get all custom claims | 获取所有自定义声明
    pub fn get_claims(&self) -> &HashMap<String, Value> {
        &self.extra
    }

    /// Check if token is expired | 检查 token 是否过期
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            let now = Utc::now().timestamp();
            now >= exp
        } else {
            false
        }
    }

    /// Get remaining time in seconds | 获取剩余时间（秒）
    pub fn remaining_time(&self) -> Option<i64> {
        self.exp.map(|exp| {
            let now = Utc::now().timestamp();
            (exp - now).max(0)
        })
    }
}

/// JWT Manager | JWT 管理器
///
/// Manages JWT token generation, validation, and parsing
/// 管理 JWT token 的生成、验证和解析
#[derive(Clone)]
pub struct JwtManager {
    /// Secret key for HMAC algorithms | HMAC 算法的密钥
    secret: String,

    /// Algorithm to use | 使用的算法
    algorithm: JwtAlgorithm,

    /// Issuer | 签发者
    issuer: Option<String>,

    /// Audience | 受众
    audience: Option<String>,
}

impl JwtManager {
    /// Create new JWT manager with HS256 algorithm | 创建使用 HS256 算法的新 JWT 管理器
    ///
    /// # Arguments | 参数
    ///
    /// * `secret` - Secret key | 密钥
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            secret: secret.into(),
            algorithm: JwtAlgorithm::HS256,
            issuer: None,
            audience: None,
        }
    }

    /// Create JWT manager with custom algorithm | 创建使用自定义算法的 JWT 管理器
    pub fn with_algorithm(secret: impl Into<String>, algorithm: JwtAlgorithm) -> Self {
        Self {
            secret: secret.into(),
            algorithm,
            issuer: None,
            audience: None,
        }
    }

    /// Set issuer | 设置签发者
    pub fn set_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set audience | 设置受众
    pub fn set_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Generate JWT token | 生成 JWT token
    ///
    /// # Arguments | 参数
    ///
    /// * `claims` - JWT claims | JWT 声明
    ///
    /// # Returns | 返回
    ///
    /// JWT token string | JWT token 字符串
    pub fn generate(&self, claims: &JwtClaims) -> TokenResult<String> {
        let mut final_claims = claims.clone();

        // Set issuer and audience if configured
        // 如果配置了签发者和受众，则设置
        if self.issuer.is_some() && final_claims.iss.is_none() {
            final_claims.iss = self.issuer.clone();
        }
        if self.audience.is_some() && final_claims.aud.is_none() {
            final_claims.aud = self.audience.clone();
        }

        let header = Header::new(self.algorithm.into());
        let encoding_key = EncodingKey::from_secret(self.secret.as_bytes());

        encode(&header, &final_claims, &encoding_key).map_err(|e| {
            TokenError::InvalidToken(format!("Failed to generate JWT: {}", e))
        })
    }

    /// Validate and parse JWT token | 验证并解析 JWT token
    ///
    /// # Arguments | 参数
    ///
    /// * `token` - JWT token string | JWT token 字符串
    ///
    /// # Returns | 返回
    ///
    /// Decoded JWT claims | 解码的 JWT 声明
    pub fn validate(&self, token: &str) -> TokenResult<JwtClaims> {
        let mut validation = Validation::new(self.algorithm.into());

        // Explicitly enable expiration validation | 明确启用过期验证
        validation.validate_exp = true;

        // Set leeway to 0 for strict validation | 设置时间偏差为0以进行严格验证
        validation.leeway = 0;

        // Configure validation | 配置验证
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
        }

        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    TokenError::TokenExpired
                }
                _ => TokenError::InvalidToken(format!("JWT validation failed: {}", e)),
            }
        })?;

        Ok(token_data.claims)
    }

    /// Decode JWT without validation (unsafe) | 不验证解码 JWT（不安全）
    ///
    /// Warning: This does not validate the signature!
    /// 警告：这不会验证签名！
    pub fn decode_without_validation(&self, token: &str) -> TokenResult<JwtClaims> {
        let mut validation = Validation::new(self.algorithm.into());
        validation.insecure_disable_signature_validation();
        validation.validate_exp = false;

        let decoding_key = DecodingKey::from_secret(self.secret.as_bytes());

        let token_data = decode::<JwtClaims>(token, &decoding_key, &validation).map_err(|e| {
            TokenError::InvalidToken(format!("Failed to decode JWT: {}", e))
        })?;

        Ok(token_data.claims)
    }

    /// Refresh JWT token | 刷新 JWT token
    ///
    /// Creates a new token with updated expiration time
    /// 创建具有更新过期时间的新 token
    ///
    /// # Arguments | 参数
    ///
    /// * `token` - Original JWT token | 原始 JWT token
    /// * `extend_seconds` - Seconds to extend | 延长的秒数
    pub fn refresh(&self, token: &str, extend_seconds: i64) -> TokenResult<String> {
        let mut claims = self.validate(token)?;

        // Update expiration time | 更新过期时间
        claims.set_expiration(extend_seconds);

        // Update issued at time | 更新签发时间
        claims.iat = Some(Utc::now().timestamp());

        self.generate(&claims)
    }

    /// Extract user ID from token without full validation | 从 token 提取用户 ID（无需完整验证）
    ///
    /// Useful for quick user identification
    /// 用于快速用户识别
    pub fn extract_login_id(&self, token: &str) -> TokenResult<String> {
        let claims = self.decode_without_validation(token)?;
        Ok(claims.login_id)
    }
}
