//! Axum提取器

use crate::auth::error::messages;
use crate::auth::token::TokenValue;
use serde_json::json;
use spring_web::axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

pub struct TokenExtractor(pub TokenValue);

impl<S> FromRequestParts<S> for TokenExtractor
where
    S: Send + Sync,
{
    type Rejection = Response;
    
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<TokenValue>() {
            Some(token) => Ok(TokenExtractor(token.clone())),
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                }))
            ).into_response()),
        }
    }
}

pub struct OptionalSaTokenExtractor(pub Option<TokenValue>);

impl<S> FromRequestParts<S> for OptionalSaTokenExtractor
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;
    
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts.extensions.get::<TokenValue>().cloned();
        Ok(OptionalSaTokenExtractor(token))
    }
}

pub struct LoginIdExtractor(pub String);

impl<S> FromRequestParts<S> for LoginIdExtractor
where
    S: Send + Sync,
{
    type Rejection = Response;
    
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        match parts.extensions.get::<String>() {
            Some(login_id) => Ok(LoginIdExtractor(login_id.clone())),
            None => Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "code": 401,
                    "message": messages::AUTH_ERROR
                }))
            ).into_response()),
        }
    }
}
