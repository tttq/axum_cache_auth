//! Token Generator | Token 生成器
//!
//! Supports multiple token styles including UUID, Random, and JWT
//! 支持多种 Token 风格，包括 UUID、随机字符串和 JWT


use chrono::Utc;
use sea_orm::prelude::Uuid;
use crate::auth::auth_config::{AuthConfig, TokenStyle};
use crate::auth::token::{JwtAlgorithm, JwtClaims, JwtManager, TokenValue};

pub struct TokenGenerator;

impl TokenGenerator {
    /// Generate token based on configuration | 根据配置生成 token
    ///
    /// # Arguments | 参数
    ///
    /// * `config` - Sa-token configuration | Sa-token 配置
    /// * `login_id` - User login ID (required for JWT) | 用户登录ID（JWT 必需）
    pub fn generate_with_login_id(config: &AuthConfig, login_id: &str) -> TokenValue {
        match config.style {
            TokenStyle::Uuid => Self::generate_uuid(),
            TokenStyle::SimpleUuid => Self::generate_simple_uuid(),
            TokenStyle::Random32 => Self::generate_random(32),
            TokenStyle::Random64 => Self::generate_random(64),
            TokenStyle::Random128 => Self::generate_random(128),
            TokenStyle::Jwt => Self::generate_jwt(config, login_id),
            TokenStyle::Hash => Self::generate_hash(login_id),
            TokenStyle::Timestamp => Self::generate_timestamp(),
            TokenStyle::Tik => Self::generate_tik(),
        }
    }
    
    /// Generate token (backward compatible) | 根据配置生成 token（向后兼容）
    pub fn generate(config: &AuthConfig) -> TokenValue {
        Self::generate_with_login_id(config, "")
    }
    
    /// 生成 UUID 风格的 token
    pub fn generate_uuid() -> TokenValue {
        TokenValue::new(Uuid::new_v4().to_string())
    }
    
    /// 生成简化的 UUID（去掉横杠）
    pub fn generate_simple_uuid() -> TokenValue {
        TokenValue::new(Uuid::new_v4().simple().to_string())
    }
    
    /// 生成随机字符串
    pub fn generate_random(length: usize) -> TokenValue {
        use sha2::{Sha256, Digest};
        let uuid = Uuid::new_v4();
        let random_bytes = uuid.as_bytes();
        let hash = Sha256::digest(random_bytes);
        let hex_string = hex::encode(hash);
        TokenValue::new(hex_string[..length.min(hex_string.len())].to_string())
    }
    
    /// Generate JWT token | 生成 JWT token
    ///
    /// # Arguments | 参数
    ///
    /// * `config` - Sa-token configuration | Sa-token 配置
    /// * `login_id` - User login ID | 用户登录ID
    pub fn generate_jwt(config: &AuthConfig, login_id: &str) -> TokenValue {
        // 如果 login_id 为空，则使用时间戳作为 login_id
        let effective_login_id = if login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            login_id.to_string()
        };
        
        // Get JWT secret key | 获取 JWT 密钥
        let secret = config.jwt_secret_key.as_ref()
            .expect("JWT secret key is required when using JWT token style");
        
        // Parse algorithm | 解析算法
        let algorithm = config.jwt_algorithm.as_ref()
            .and_then(|alg| Self::parse_jwt_algorithm(alg))
            .unwrap_or(JwtAlgorithm::HS256);
        
        // Create JWT manager | 创建 JWT 管理器
        let mut jwt_manager = JwtManager::with_algorithm(secret, algorithm);
        
        if let Some(ref issuer) = config.jwt_issuer {
            jwt_manager = jwt_manager.set_issuer(issuer);
        }
        
        if let Some(ref audience) = config.jwt_audience {
            jwt_manager = jwt_manager.set_audience(audience);
        }
        
        // Create claims | 创建声明
        let mut claims = JwtClaims::new(effective_login_id);
        
        // Set expiration | 设置过期时间
        if config.expire > 0 {
            claims.set_expiration(config.expire as i64);
        }
        
        // Generate JWT token | 生成 JWT token
        match jwt_manager.generate(&claims) {
            Ok(token) => TokenValue::new(token),
            Err(e) => {
                eprintln!("Failed to generate JWT token: {:?}", e);
                // Fallback to UUID | 回退到 UUID
                Self::generate_uuid()
            }
        }
    }
    
    /// Parse JWT algorithm from string | 从字符串解析 JWT 算法
    fn parse_jwt_algorithm(alg: &str) -> Option<JwtAlgorithm> {
        match alg.to_uppercase().as_str() {
            "HS256" => Some(JwtAlgorithm::HS256),
            "HS384" => Some(JwtAlgorithm::HS384),
            "HS512" => Some(JwtAlgorithm::HS512),
            "RS256" => Some(JwtAlgorithm::RS256),
            "RS384" => Some(JwtAlgorithm::RS384),
            "RS512" => Some(JwtAlgorithm::RS512),
            "ES256" => Some(JwtAlgorithm::ES256),
            "ES384" => Some(JwtAlgorithm::ES384),
            _ => None,
        }
    }
    
    /// Generate Hash style token | 生成 Hash 风格 token
    ///
    /// Uses SHA256 hash of login_id + timestamp + random UUID
    /// 使用 SHA256 哈希：login_id + 时间戳 + 随机 UUID
    ///
    /// # Arguments | 参数
    ///
    /// * `login_id` - User login ID | 用户登录ID
    pub fn generate_hash(login_id: &str) -> TokenValue {
        use sha2::{Sha256, Digest};
        // 如果 login_id 为空，使用时间戳代替
        let login_id_value = if login_id.is_empty() {
            Utc::now().timestamp_millis().to_string()
        } else {
            login_id.to_string()
        };
        
        let timestamp = Utc::now().timestamp_millis();
        let uuid = Uuid::new_v4();
        let data = format!("{}{}{}", login_id_value, timestamp, uuid);
        
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        let hash = hex::encode(result);
        
        TokenValue::new(hash)
    }
    
    /// Generate Timestamp style token | 生成时间戳风格 token
    ///
    /// Format: timestamp_milliseconds + 16-char random suffix
    /// 格式：毫秒级时间戳 + 16位随机后缀
    ///
    /// Example: 1760403556789_a3b2c1d4e5f6g7h8
    /// 示例：1760403556789_a3b2c1d4e5f6g7h8
    pub fn generate_timestamp() -> TokenValue {
        use chrono::Utc;
        use sha2::{Sha256, Digest};
        
        let timestamp = Utc::now().timestamp_millis();
        let uuid = Uuid::new_v4();
        
        // Generate random suffix | 生成随机后缀
        let mut hasher = Sha256::new();
        hasher.update(uuid.as_bytes());
        let result = hasher.finalize();
        let suffix = hex::encode(&result[..8]); // 16 characters
        
        TokenValue::new(format!("{}_{}", timestamp, suffix))
    }
    
    /// Generate Tik style token | 生成 Tik 风格 token
    ///
    /// Short 8-character alphanumeric token (URL-safe)
    /// 短小精悍的8位字母数字 token（URL安全）
    ///
    /// Character set: A-Z, a-z, 0-9 (62 characters)
    /// 字符集：A-Z, a-z, 0-9（62个字符）
    ///
    /// Example: aB3dE9fG
    /// 示例：aB3dE9fG
    pub fn generate_tik() -> TokenValue {
        use sha2::{Sha256, Digest};
        
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const TOKEN_LENGTH: usize = 8;
        
        let uuid = Uuid::new_v4();
        let mut hasher = Sha256::new();
        hasher.update(uuid.as_bytes());
        let hash = hasher.finalize();
        
        let mut token = String::with_capacity(TOKEN_LENGTH);
        for i in 0..TOKEN_LENGTH {
            let idx = (hash[i] as usize) % CHARSET.len();
            token.push(CHARSET[idx] as char);
        }
        
        TokenValue::new(token)
    }
}
