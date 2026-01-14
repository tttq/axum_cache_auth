
//! Axum请求/响应适配器

use std::collections::HashMap;
use http::{Request, Response};
use serde::Serialize;
use crate::auth::context::{AxumRequest, AxumResponse, CookieOptions};

/// Axum请求适配器
pub struct AxumRequestAdapter<'a, T> {
    request: &'a Request<T>,
}

impl<'a, T> AxumRequestAdapter<'a, T> {
    pub fn new(request: &'a Request<T>) -> Self {
        Self { request }
    }
}

impl<'a, T> AxumRequest for AxumRequestAdapter<'a, T> {
    fn get_header(&self, name: &str) -> Option<String> {
        self.request.headers().get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }
    
    fn get_cookie(&self, name: &str) -> Option<String> {
        self.request.headers().get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| parse_cookies(cookies).get(name).cloned())
    }
    
    fn get_param(&self, name: &str) -> Option<String> {
        self.request
            .uri()
            .query()
            .and_then(|query| parse_query_string(query).get(name).cloned())
    }
    
    fn get_path(&self) -> String {
        self.request.uri().path().to_string()
    }
    
    fn get_method(&self) -> String {
        self.request.method().to_string()
    }
}

/// Axum响应适配器
pub struct AxumResponseAdapter<T> {
    response: Response<T>,
}

impl<T> AxumResponseAdapter<T> {
    pub fn new(response: Response<T>) -> Self {
        Self { response }
    }
    
    pub fn into_response(self) -> Response<T> {
        self.response
    }
}

impl<T> AxumResponse for AxumResponseAdapter<T> {
    fn set_header(&mut self, name: &str, value: &str) {
        if let Ok(header_name) = http::header::HeaderName::from_bytes(name.as_bytes()) {
            if let Ok(header_value) = http::header::HeaderValue::from_str(value) {
                self.response.headers_mut().insert(header_name, header_value);
            }
        }
    }
    
    fn set_cookie(&mut self, name: &str, value: &str, options: CookieOptions) {
        let mut cookie = format!("{}={}", name, value);
        
        if let Some(domain) = options.domain {
            cookie.push_str(&format!("; Domain={}", domain));
        }
        if let Some(path) = options.path {
            cookie.push_str(&format!("; Path={}", path));
        }
        if let Some(max_age) = options.max_age {
            cookie.push_str(&format!("; Max-Age={}", max_age));
        }
        if options.http_only {
            cookie.push_str("; HttpOnly");
        }
        if options.secure {
            cookie.push_str("; Secure");
        }
        
        self.set_header("Set-Cookie", &cookie);
    }
    
    fn set_status(&mut self, status: u16) {
        *self.response.status_mut() = http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::OK);
    }
    
    fn set_json_body<U: Serialize>(&mut self, _body: U) -> Result<(), serde_json::Error> {
        // 需要替换response body，在axum中比较复杂
        Ok(())
    }
}

/// 解析 Cookie 字符串
fn parse_cookies(cookie_header: &str) -> HashMap<String, String> {
    let mut cookies = HashMap::new();
    for pair in cookie_header.split(';') {
        let parts: Vec<&str> = pair.trim().splitn(2, '=').collect();
        if parts.len() == 2 {
            cookies.insert(parts[0].to_string(), parts[1].to_string());
        }
    }
    cookies
}

/// 解析查询字符串
fn parse_query_string(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in query.split('&') {
        let parts: Vec<&str> = pair.splitn(2, '=').collect();
        if parts.len() == 2 {
            params.insert(
                urlencoding::decode(parts[0]).unwrap_or_default().to_string(),
                urlencoding::decode(parts[1]).unwrap_or_default().to_string(),
            );
        }
    }
    params
}
