use schemars::JsonSchema;
use serde::Deserialize;
use spring::config::Configurable;

spring::submit_config_schema!("storage", StorageConfig);

#[derive(Debug, Configurable, Clone, JsonSchema, Deserialize)]
#[config_prefix = "storage"]
pub struct StorageConfig {
    /// The URI for connecting to the Redis server. For example:
    /// <redis://127.0.0.1/>
    pub uri: String,

    /// The new connection will time out operations after `response_timeout` has passed.
    pub response_timeout: Option<u64>,

    /// Each connection attempt to the server will time out after `connection_timeout`.
    pub connection_timeout: Option<u64>,

    /// number_of_retries times, with an exponentially increasing delay
    pub number_of_retries: Option<usize>,

    /// The resulting duration is calculated by taking the base to the `n`-th power,
    /// where `n` denotes the number of past attempts.
    pub exponent_base: Option<f32>,

    /// Apply a maximum delay between connection attempts. The delay between attempts won't be longer than max_delay milliseconds.
    pub max_delay: Option<u64>,

    /// The prefix to use for all keys.
    #[serde(default = "default_prefix_key")]
    pub key_prefix: String,

    /// The maximum number of items to store in the local cache.
    #[serde(default = "default_local_max_capacity")]
    pub local_max_capacity: u64,

    /// The default time to live for items in the remote cache.
    #[serde(default = "default_default_ttl")]
    pub default_ttl: u64,

    /// The maximum time to live for items in the remote cache.
    #[serde(default = "default_time_to_idle")]
    pub time_to_idle: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            uri: "redis://127.0.0.1/".to_string(),
            response_timeout: None,
            connection_timeout: None,
            number_of_retries: None,
            exponent_base: None,
            max_delay: None,
            key_prefix: default_prefix_key(),
            local_max_capacity: default_local_max_capacity(),
            default_ttl: default_default_ttl(),
            time_to_idle: default_time_to_idle(),
        }
    }
}
/// 默认缓存前缀
fn default_prefix_key() -> String{
    "storage".to_string()
}
/// 默认本地缓存最大容量
fn default_local_max_capacity() -> u64{
    100
}
/// 默认缓存过期时间
fn default_default_ttl() -> u64{
    3600
}
/// 默认缓存过期时间
fn default_time_to_idle() -> u64{
    1800
}
