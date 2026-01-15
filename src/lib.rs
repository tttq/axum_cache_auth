use crate::auth::auth_config::AuthConfig;
use crate::auth::layer::{AuthValidTrait, TokenLayer, TokenState};
use crate::store::hybrid_storage::HybridStorage;
use crate::store::local_storage::LocalStorage;
use crate::store::redis_storage::RedisStorage;
use crate::store::storage_config::StorageConfig;
use anyhow::Context;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::Client;
use crate::auth::utils::StpUtil;
use serde::de::DeserializeOwned;
use spring::config::env::Env;
use spring::config::toml::TomlConfigRegistry;
use spring::config::{ConfigRegistry, Configurable};
use spring::error::AppError;
use spring_web::aide::axum::ApiRouter;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use crate::auth::manager::CustomTimeoutTrait;

pub mod store;
pub mod auth;


pub struct CacheRouterPlugin;

impl CacheRouterPlugin {
    pub async fn create_auth_router(&self, config_path: &str, auth_valid_trait:Arc<dyn AuthValidTrait>, custom_timeout_trait:Option<Arc<dyn CustomTimeoutTrait>>) -> (ApiRouter, HybridStorage) {
        let app = get_config_registry(config_path);
        let store_config = app
            .get_config::<StorageConfig>()
            .expect("redis plugin config load failed");

        let auth_config = app
            .get_config::<AuthConfig>()
            .expect("redis plugin config load failed");

        let connect = Self::redis_connect(store_config.clone()).await.expect("redis connect failed");
        let redis_storage =  RedisStorage::new(connect, store_config.key_prefix.clone());
        let local_storage = Self::local_connect(store_config.clone()).await.expect("local connect failed");
        let hybrid_storage = HybridStorage::new(local_storage, redis_storage, auth_config.clone().storage);
        let state = TokenState::new(Arc::new(hybrid_storage.clone()),Arc::new(auth_config),auth_valid_trait,custom_timeout_trait);
        StpUtil::init_manager(state.manager.clone());
        (spring_web::handler::auto_router()
             .layer(TokenLayer::new(state.clone())),hybrid_storage)
    }
}

impl CacheRouterPlugin {

    /// redis缓存
    async fn redis_connect(config: StorageConfig) -> spring::error::Result<ConnectionManager> {
        let url = config.uri;
        let client = Client::open(url.clone())
            .with_context(|| format!("redis connect failed:{}", url.clone()))?;

        let mut conn_config = ConnectionManagerConfig::new();

        if let Some(exponent_base) = config.exponent_base {
            conn_config = conn_config.set_exponent_base(exponent_base);
        }
        if let Some(number_of_retries) = config.number_of_retries {
            conn_config = conn_config.set_number_of_retries(number_of_retries);
        }
        if let Some(max_delay) = config.max_delay {
            conn_config = conn_config.set_max_delay(Duration::from_millis(max_delay));
        }
        if let Some(response_timeout) = config.response_timeout {
            conn_config = conn_config.set_response_timeout(Some(Duration::from_millis(response_timeout)));
        }
        if let Some(connection_timeout) = config.connection_timeout {
            conn_config =
                conn_config.set_connection_timeout(Some(Duration::from_millis(connection_timeout)));
        }

        Ok(client
            .get_connection_manager_with_config(conn_config)
            .await
            .with_context(|| format!("redis connect failed:{}", url.clone()))?)
    }
    /// 本地缓存
    async  fn local_connect(config: StorageConfig) -> spring::error::Result<LocalStorage> {
        Ok(LocalStorage::new(
            Some(&config.key_prefix),
            config.local_max_capacity,
            Duration::from_secs(config.default_ttl),
            Duration::from_secs(config.time_to_idle))
        )
    }
}


/// 通过名称获取配置项
pub fn get_config_form_name<T: spring::config::Configurable>(config_name: &str)->Result<T,AppError>
where
    T: DeserializeOwned + Configurable,
{
    let config_path = format!("src/config/{}", config_name);
    get_config_from_path(&config_path)
}

/// 通过全路径获取配置项
pub fn get_config_from_path<T: spring::config::Configurable>(config_path: &str)->Result<T,AppError>
where
    T: DeserializeOwned + Configurable,
{
    let app = get_config_registry(config_path);
    Ok(app.get_config::<T>().expect("app_config not found"))
}

/// 通过路径获取配置注册项
pub fn get_config_registry(config_path: &str)->TomlConfigRegistry
{
    let env = Env::from_env();
    TomlConfigRegistry::new(Path::new(config_path), env).expect("加载配置文件失败")
}