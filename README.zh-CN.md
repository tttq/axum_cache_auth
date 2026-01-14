# axum_cache_auth

## 项目概述

`axum_cache_auth` 是一个基于 Rust 语言开发的身份验证与缓存库，专为 Axum 框架设计，提供了完整的身份验证解决方案和混合缓存机制。该库结合了本地缓存和 Redis 缓存，实现了高效的身份验证和授权管理。

### 功能特性

- **混合缓存机制**：结合本地缓存和 Redis 缓存，提高缓存效率
- **身份验证中间件**：提供基于 Token 的身份验证中间件
- **灵活的存储配置**：支持多种缓存存储方式的配置
- **可扩展的身份验证**：支持自定义身份验证逻辑
- **Spring 框架集成**：与 Rust Spring 框架无缝集成
- **配置驱动**：支持通过配置文件灵活配置

### 技术架构

- **语言**：Rust
- **核心依赖**：
  - `axum`：Web 框架
  - `redis`：Redis 客户端
  - `spring`：Rust 应用框架
  - `serde`：序列化/反序列化库
  - `anyhow`：错误处理库

## 安装与配置

### 安装

在 `Cargo.toml` 文件中添加依赖：

```toml
dependencies =
    axum_cache_auth = { version = "0.1.1", git = "https://github.com/tttq/axum_cache_auth.git" }
    axum = "0.7"
    redis = "0.24"
    spring = "0.1"
```

### 配置

1. **缓存配置**：

在配置文件（如 `config.toml`）中添加缓存配置：

```toml
[storage]
# Redis 连接 URI
uri = "redis://localhost:6379"
# 缓存键前缀
key_prefix = "my_app:"
# 指数退避基础值
# exponent_base = 2
# 最大重试次数
# number_of_retries = 3
# 最大延迟时间（毫秒）
# max_delay = 1000
# 响应超时时间（毫秒）
# response_timeout = 5000
# 连接超时时间（毫秒）
# connection_timeout = 5000
# 本地缓存最大容量
local_max_capacity = 10000
# 默认过期时间（秒）
default_ttl = 3600
# 空闲时间（秒）
time_to_idle = 1800
```

2. **身份验证配置**：

在配置文件中添加身份验证配置：

```toml
[auth]
# 存储类型：local 或 redis
storage = "hybrid"
# Token 过期时间（秒）
token_ttl = 3600
# 刷新 Token 过期时间（秒）
refresh_token_ttl = 86400
# JWT 密钥（用于签名）
jwt_secret = "your_jwt_secret_key"
# JWT 算法
algorithm = "HS256"
```

## 使用指南

### 基本使用

1. **创建身份验证路由器**：

```rust
use axum_cache_auth::CacheRouterPlugin;
use spring::app::AppBuilder;

#[tokio::main]
async fn main() {
    let plugin = CacheRouterPlugin;
    let auth_valid_trait = Arc::new(MyAuthValidTrait::new());
    
    // 创建身份验证路由器
    let (auth_router, hybrid_storage) = plugin
        .create_auth_router("src/config/config.toml", auth_valid_trait)
        .await;
    
    // 构建 Axum 应用
    let app = axum::Router::new()
        .merge(auth_router)
        .route("/", axum::routing::get(|| async { "Hello, World!" }));
    
    // 启动服务器
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

2. **与 spring-web 集成**：

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

3. **实现自定义身份验证逻辑**：

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
        // 实现自定义权限验证逻辑
        // 例如：检查用户是否有访问该路径的权限
        true
    }

    async fn has_role(&self, _manager: Arc<TokenManager>, _path: String, _role_code: Option<String>, _role_key: Option<String>) -> bool {
        // 实现自定义角色验证逻辑
        // 例如：检查用户是否有指定角色
        true
    }
}
```

4. **使用混合存储**：

```rust
use axum_cache_auth::store::hybrid_storage::HybridStorage;

// 存储数据
let key = "my_key";
let value = "my_value";
hybrid_storage.set(key, value, Duration::from_secs(3600)).await?;

// 获取数据
let result = hybrid_storage.get(key).await?;

// 删除数据
hybrid_storage.delete(key).await?;
```

5. **使用身份验证中间件**：

```rust
use axum_cache_auth::auth::layer::TokenLayer;
use axum_cache_auth::auth::layer::TokenState;

// 创建 TokenState
let token_state = TokenState::new(
    Arc::new(hybrid_storage),
    Arc::new(auth_config),
    auth_valid_trait
);

// 创建身份验证中间件
let token_layer = TokenLayer::new(token_state);

// 应用中间件
let app = axum::Router::new()
    .route("/protected", axum::routing::get(protected_handler))
    .layer(token_layer);

async fn protected_handler() -> &'static str {
    "This is a protected route"
}
```

## 注意事项

### 环境要求

- **Rust 版本**：1.65.0 及以上
- **Axum 版本**：0.7.x
- **Redis 版本**：5.0 及以上（如果使用 Redis 缓存）

### 限制条件

1. 目前仅支持基于 Token 的身份验证
2. Redis 连接需要在配置文件中正确配置
3. 本地缓存容量有限，建议根据实际需求调整
4. 身份验证中间件需要与 Axum 框架配合使用

### 常见问题

1. **问题**：身份验证失败
   **解决方案**：检查 Token 是否有效，确保自定义身份验证逻辑正确实现

2. **问题**：Redis 连接失败
   **解决方案**：检查 Redis 服务器是否正常运行，配置文件中的连接 URI 是否正确

3. **问题**：缓存数据不一致
   **解决方案**：确保混合缓存的配置正确，必要时调整缓存过期时间

## 项目目录结构

```
axum_cache_auth/
├── src/
│   ├── auth/                 # 身份验证相关代码
│   │   ├── auth_config.rs    # 身份验证配置
│   │   ├── layer.rs          # 身份验证中间件
│   │   └── utils.rs          # 身份验证工具函数
│   ├── store/                # 缓存存储相关代码
│   │   ├── hybrid_storage.rs # 混合存储实现
│   │   ├── localStorage.rs   # 本地存储实现
│   │   ├── redis_storage.rs  # Redis 存储实现
│   │   └── storage_config.rs # 存储配置
│   └── lib.rs                # 库入口文件
├── Cargo.toml                # 依赖配置
└── README.md                 # 项目文档
```

### 文件用途说明

| 文件/文件夹 | 用途 |
| --- | --- |
| `src/auth/auth_config.rs` | 定义身份验证配置结构 AuthConfig |
| `src/auth/layer.rs` | 实现身份验证中间件 TokenLayer 和相关 trait |
| `src/auth/utils.rs` | 提供身份验证相关的工具函数 |
| `src/store/hybrid_storage.rs` | 实现混合存储，结合本地缓存和 Redis 缓存 |
| `src/store/localStorage.rs` | 实现本地缓存存储 |
| `src/store/redis_storage.rs` | 实现 Redis 缓存存储 |
| `src/store/storage_config.rs` | 定义存储配置结构 StorageConfig |
| `src/lib.rs` | 库的入口文件，导出核心功能和类型 |
| `Cargo.toml` | 项目依赖和构建配置 |
| `README.md` | 项目文档，包含使用说明和 API 参考 |