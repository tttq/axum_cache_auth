//! Token 验证器

use crate::auth::error::{TokenError, TokenResult};
use crate::auth::token::TokenInfo;
/// Token 验证器 | Token Validator
///
/// 用于验证 Token 的有效性和格式
/// Used to validate token validity and format
pub struct TokenValidator;

impl TokenValidator {
    /// 验证 token 是否有效 | Validate if Token is Valid
    /// 
    /// 检查 Token 是否过期
    /// Check if token is expired
    /// 
    /// # 参数 | Parameters
    /// - `token_info`: Token 信息 | Token information
    /// 
    /// # 返回 | Returns
    /// - `Ok(())`: Token 有效 | Token is valid
    /// - `Err(TokenExpired)`: Token 已过期 | Token has expired
    pub fn validate(token_info: &TokenInfo) -> TokenResult<()> {
        // 检查是否过期 | Check if expired
        if token_info.is_expired() {
            return Err(TokenError::TokenExpired);
        }
        
        Ok(())
    }
    
    /// 检查 token 格式是否正确 | Check if Token Format is Correct
    /// 
    /// 验证 Token 的基本格式要求
    /// Validate basic format requirements of token
    /// 
    /// # 参数 | Parameters
    /// - `token`: Token 字符串 | Token string
    /// 
    /// # 返回 | Returns
    /// - `Ok(())`: 格式正确 | Format is correct
    /// - `Err(TokenEmpty)`: Token 为空 | Token is empty
    /// - `Err(TokenTooShort)`: Token 太短 | Token is too short
    pub fn check_format(token: &str) -> TokenResult<()> {
        if token.is_empty() {
            return Err(TokenError::TokenEmpty);
        }
        
        if token.len() < 8 {
            return Err(TokenError::TokenTooShort);
        }
        
        Ok(())
    }
}
