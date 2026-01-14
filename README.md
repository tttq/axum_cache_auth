# axum_cache_auth

## Project Overview

`axum_cache_auth` is an authentication and caching library developed in Rust, designed specifically for the Axum framework. It provides a complete authentication solution and hybrid caching mechanism, combining local cache and Redis cache to achieve efficient authentication and authorization management.

### Features

- **Hybrid Cache Mechanism**: Combines local cache and Redis cache to improve cache efficiency
- **Authentication Middleware**: Provides Token-based authentication middleware
- **Flexible Storage Configuration**: Supports configuration of multiple cache storage methods
- **Extensible Authentication**: Supports custom authentication logic
- **Spring Framework Integration**: Seamlessly integrates with Rust Spring framework
- **Configuration Driven**: Supports flexible configuration through configuration files

### Technical Architecture

- **Language**: Rust
- **Core Dependencies**:
  - `axum`: Web framework
  - `redis`: Redis client
  - `spring`: Rust application framework
  - `serde`: Serialization/deserialization library
  - `anyhow`: Error handling library

## Installation and Configuration

### Installation

Add dependencies to your `Cargo.toml` file:

```toml
dependencies =
    axum_cache_auth = { version = "0.1.1", git = "https://github.com/tttq/axum_cache_auth.git" }
    axum = "0.7"
    redis = "0.24"
    spring = "0.1"
```

### Configuration

1. **Cache Configuration**:

Add cache configuration to your configuration file (e.g., `config.toml`):

```toml
[storage]
# Redis connection URI
uri = "redis://localhost:6379"
# Cache key prefix
key_prefix = "my_app:"
# Exponential backoff base value
# exponent_base = 2
# Maximum number of retries
# number_of_retries = 3
# Maximum delay time (milliseconds)
# max_delay = 1000
# Response timeout (milliseconds)
# response_timeout = 5000
# Connection timeout (milliseconds)
# connection_timeout = 5000
# Local cache maximum capacity
local_max_capacity = 10000
# Default TTL (seconds)
default_ttl = 3600
# Time to idle (seconds)
time_to_idle = 1800
```

2. **Authentication Configuration**:

Add authentication configuration to your configuration file:

```toml
[auth]
# Storage type: local or redis
storage = "hybrid"
# Token TTL (seconds)
token_ttl = 3600
# Refresh token TTL (seconds)
refresh_token_ttl = 86400
# JWT secret key (for signing)
jwt_secret = "your_jwt_secret_key"
# JWT algorithm
algorithm = "HS256"
```

## Usage Guide

### Basic Usage

1. **Create Authentication Router**:

```rust
use axum_cache_auth::CacheRouterPlugin;
use spring::app::AppBuilder;

#[tokio::main]
async fn main() {
    let plugin = CacheRouterPlugin;
    let auth_valid_trait = Arc::new(MyAuthValidTrait::new());
    
    // Create authentication router
    let (auth_router, hybrid_storage) = plugin
        .create_auth_router("src/config/config.toml", auth_valid_trait)
        .await;
    
    // Build Axum application
    let app = axum::Router::new()
        .merge(auth_router)
        .route("/", axum::routing::get(|| async { "Hello, World!" }));
    
    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

2. **Integration with spring-web**:

```rust
use axum_cache_auth::AuthPlugin;
use spring::App;
use spring_web::plugin::WebPlugin;
use auto_field_trait::HookedSeaOrmPlugin;
use spring_snowflake::plugin::SnowflakePlugin;
use auto_field_trait::AutoFieldPlugin;

#[tokio::main]
async fn main() {
    let config_path = "src/config/app.toml";
    let (router, store) = AuthPlugin::create_auth_router(config_path).await;
    App::new()
        .use_config_file(config_path)
        .add_plugin(WebPlugin)
        .add_plugin(HookedSeaOrmPlugin)
        .add_plugin(SnowflakePlugin)
        .add_plugin(AutoFieldPlugin)
        .add_component(store)
        .add_router(router)
        .run()
        .await
}
```

3. **Implement Custom Authentication Logic**:

```rust
use axum_cache_auth::auth::layer::AuthValidTrait;
use axum_cache_auth::auth::utils::TokenManager;
use spring::error::Result;
use std::sync::Arc;

struct MyAuthValidTrait;

impl MyAuthValidTrait {
    fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuthValidTrait for MyAuthValidTrait {
    async fn has_permission(&self, manager: Arc<TokenManager>, path: String, permission_code: Option<String>, key: Option<String>) -> bool {
        // Implement custom permission validation logic
        // For example: Check if the user has permission to access the path
        true
    }

    async fn has_role(&self, _manager: Arc<TokenManager>, _path: String, _role_code: Option<String>, _role_key: Option<String>) -> bool {
        // Implement custom role validation logic
        // For example: Check if the user has the specified role
        true
    }
}
```

4. **Use Hybrid Storage**:

```rust
use axum_cache_auth::store::hybrid_storage::HybridStorage;

// Store data
let key = "my_key";
let value = "my_value";
hybrid_storage.set(key, value, Duration::from_secs(3600)).await?;

// Get data
let result = hybrid_storage.get(key).await?;

// Delete data
hybrid_storage.delete(key).await?;
```

5. **Use Authentication Middleware**:

```rust
use axum_cache_auth::auth::layer::TokenLayer;
use axum_cache_auth::auth::layer::TokenState;

// Create TokenState
let token_state = TokenState::new(
    Arc::new(hybrid_storage),
    Arc::new(auth_config),
    auth_valid_trait
);

// Create authentication middleware
let token_layer = TokenLayer::new(token_state);

// Apply middleware
let app = axum::Router::new()
    .route("/protected", axum::routing::get(protected_handler))
    .layer(token_layer);

async fn protected_handler() -> &'static str {
    "This is a protected route"
}
```

## Notes

### Environment Requirements

- **Rust Version**: 1.65.0 or higher
- **Axum Version**: 0.7.x
- **Redis Version**: 5.0 or higher (if using Redis cache)

### Limitations

1. Currently only supports Token-based authentication
2. Redis connection needs to be correctly configured in the configuration file
3. Local cache capacity is limited, it is recommended to adjust according to actual needs
4. Authentication middleware needs to be used with Axum framework

### Common Issues

1. **Issue**: Authentication failure
   **Solution**: Check if the Token is valid, ensure the custom authentication logic is correctly implemented

2. **Issue**: Redis connection failure
   **Solution**: Check if the Redis server is running normally, and if the connection URI in the configuration file is correct

3. **Issue**: Cache data inconsistency
   **Solution**: Ensure the hybrid cache configuration is correct, adjust the cache expiration time if necessary

## Project Directory Structure

```
axum_cache_auth/
├── src/
│   ├── auth/                 # Authentication related code
│   │   ├── auth_config.rs    # Authentication configuration
│   │   ├── layer.rs          # Authentication middleware
│   │   └── utils.rs          # Authentication utility functions
│   ├── store/                # Cache storage related code
│   │   ├── hybrid_storage.rs # Hybrid storage implementation
│   │   ├── localStorage.rs   # Local storage implementation
│   │   ├── redis_storage.rs  # Redis storage implementation
│   │   └── storage_config.rs # Storage configuration
│   └── lib.rs                # Library entry file
├── Cargo.toml                # Dependency configuration
└── README.md                 # Project documentation
```

### File Usage Description

| File/Folder | Purpose |
| --- | --- |
| `src/auth/auth_config.rs` | Defines authentication configuration structure AuthConfig |
| `src/auth/layer.rs` | Implements authentication middleware TokenLayer and related traits |
| `src/auth/utils.rs` | Provides authentication-related utility functions |
| `src/store/hybrid_storage.rs` | Implements hybrid storage, combining local cache and Redis cache |
| `src/store/localStorage.rs` | Implements local cache storage |
| `src/store/redis_storage.rs` | Implements Redis cache storage |
| `src/store/storage_config.rs` | Defines storage configuration structure StorageConfig |
| `src/lib.rs` | Library entry point, exporting core functions and types |
| `Cargo.toml` | Project dependencies and build configuration |
| `README.md` | Project documentation, including usage instructions and API reference |