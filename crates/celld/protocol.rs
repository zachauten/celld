// Copyright 2026 Deno Land Inc. Apache-2.0 license.

//! Durable types on the bucket contract between deployment tools and celld.
//! These objects are the interface; nothing else is exchanged.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeMap;

/// `deploy/<script>/<version>/manifest.json` — the normalized thing celld reads
/// to know what to run. The script name is deployment identity, not a fleet
/// selector: one fleet has one current application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(default = "legacy_manifest_schema_version")]
    pub schema_version: u32,
    pub version: String,
    pub script_name: String,
    /// Absent for Wrangler asset-only deployments.
    pub main_module: Option<String>,
    /// Durable Object classes exported by the worker.
    pub do_classes: Vec<String>,
    /// Subset of `do_classes` that are SQLite-backed (from migrations).
    pub sqlite_classes: Vec<String>,
    pub modules: Vec<ModuleRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assets: Option<AssetManifestRef>,
    /// Cron trigger expressions from the config's `triggers.crons`. They are
    /// deployment state rather than cell state: the reserved cron cell reads
    /// them from the manifest it is running under, so changing a schedule
    /// needs no migration of an already-armed alarm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crons: Vec<String>,
    /// Push consumers attached to this Worker deployment. Producer bindings
    /// remain in `raw_metadata.bindings`, because they become values in `env`;
    /// consumers drive the broker and have no environment binding.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queue_consumers: Vec<QueueConsumerConfig>,
    /// The container classes of this deployment: class, image id, and the
    /// instance shape. Each image tar is at `deploy/images/<id>.tar`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub containers: Vec<crate::container::ContainerSpec>,
    /// The `celld-fence` image `celld deploy` built beside the container
    /// images: the node runs it once, privileged, to fence its container
    /// bridges before any container starts. `None` in a deployment without
    /// containers, and in one made by a celld that predates the fence,
    /// which a node then refuses to start containers for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fence_image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sip: Option<SipManifestConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_features: Vec<String>,
    /// wrangler's raw metadata, retained verbatim for anything we don't yet model.
    pub raw_metadata: serde_json::Value,
}

fn legacy_manifest_schema_version() -> u32 {
    1
}

/// Manifest `required_features` values this build can load. A manifest
/// requiring anything else must be rejected up front: `ModuleRef` tolerates
/// unknown fields, so an older node would otherwise deserialize the manifest
/// partially and fail (or misbehave) at worker load instead.
pub const SUPPORTED_DEPLOYMENT_FEATURES: &[&str] = &[
    FEATURE_ASSETS_V1,
    FEATURE_CONTAINERS_V1,
    FEATURE_CRON_V1,
    FEATURE_D1_V1,
    FEATURE_KV_V1,
    FEATURE_QUEUES_V1,
    FEATURE_SQLITE_VEC_V1,
    FEATURE_R2_V1,
    FEATURE_WASM_V1,
    FEATURE_WORKFLOWS_V1,
    FEATURE_PYTHON_WORKERS_V1,
    FEATURE_SIP_V1,
];

pub const FEATURE_SIP_V1: &str = "sip-v1";
pub const FEATURE_ASSETS_V1: &str = "assets-v1";
/// A deployment with `containers`. Required because a build without the
/// container engine would load the manifest, build a `ctx` with no
/// `container`, and fail only when the object first touches it.
pub const FEATURE_CONTAINERS_V1: &str = "containers-v1";
/// A deployment with D1 databases. Required because a build without the
/// reserved `__D1Database` class would load the manifest and then fail every
/// `env.DB` call at request time, on a node the developer is not watching —
/// the gate moves that failure to the deploy.
pub const FEATURE_D1_V1: &str = "d1-v1";
/// A deployment with cron triggers. Required because a build without the
/// reserved cron cell would load the manifest, ignore `crons`, and silently
/// never fire — the quiet failure the gate exists to prevent.
pub const FEATURE_CRON_V1: &str = "cron-v1";
/// A deployment with `r2_buckets` bindings. Required because a build without
/// the R2 binding would load the manifest and then throw on every method the
/// application calls, at request time, on a node the developer is not
/// watching — the gate moves that failure to the deploy.
pub const FEATURE_R2_V1: &str = "r2-v1";
pub const FEATURE_SQLITE_VEC_V1: &str = "sqlite-vec-v1";
pub const FEATURE_WASM_V1: &str = "wasm-v1";
/// A deployment whose `main` is a `.py` file. Required because the bundle
/// passes the Workers SDK's own body streams back to `Response`, and a node
/// whose body streams do not report `ReadableStream` as their constructor
/// fails those requests with a Python `TypeError`.
pub const FEATURE_PYTHON_WORKERS_V1: &str = "python-workers-v1";
/// A deployment with `workflows` bindings. Required because a build without
/// the reserved workflow cell would load the manifest, build an `env` missing
/// the binding, and fail only when the application first calls `create()` —
/// in production, with an error that blames the application.
pub const FEATURE_WORKFLOWS_V1: &str = "workflows-v1";

/// A deployment with `kv_namespaces` bindings. Gated for the same reason
/// workflows are, and not for D1's reason: a build without KV would load the
/// manifest, build an `env` with no `KV` on it, and fail only when the
/// application first reads a key. D1's absence fails loudly at load instead,
/// because its reserved class is in `do_classes` and the loader refuses a
/// class it does not know.
pub const FEATURE_KV_V1: &str = "kv-v1";

/// A deployment with a Queue producer or consumer. A node without the broker
/// would otherwise omit a producer binding or silently stop consuming.
pub const FEATURE_QUEUES_V1: &str = "queues-v1";

pub const QUEUE_CONSUMER_ATTACHMENT_SCHEMA_VERSION: u32 = 1;

/// `deploy/queues/<queue>/consumer.json` — the one deployment allowed to
/// consume a fleet-global queue. The record keeps an exact deployment
/// reference, because the script's named pointer can move independently
/// between the attachment read and the Worker load.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueConsumerAttachment {
    pub schema_version: u32,
    pub queue: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumer: Option<QueueConsumerDeployment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueConsumerDeployment {
    pub script_name: String,
    pub version: String,
    pub prefix: String,
}

pub fn queue_consumer_attachment_key(queue: &str) -> Option<String> {
    celld_logic::cell::valid_cell_scope(queue)
        .then(|| format!("deploy/queues/{queue}/consumer.json"))
}

pub fn validate_queue_consumer_attachment(
    expected_queue: &str,
    attachment: &QueueConsumerAttachment,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        attachment.schema_version == QUEUE_CONSUMER_ATTACHMENT_SCHEMA_VERSION,
        "queue consumer attachment for {expected_queue:?} has unsupported schema version {}",
        attachment.schema_version
    );
    anyhow::ensure!(
        attachment.queue == expected_queue,
        "queue consumer attachment for {expected_queue:?} names queue {:?}",
        attachment.queue
    );
    if let Some(consumer) = &attachment.consumer {
        anyhow::ensure!(
            !consumer.script_name.is_empty()
                && !consumer.version.is_empty()
                && consumer.prefix
                    == format!("deploy/{}/{}", consumer.script_name, consumer.version),
            "queue consumer attachment for {expected_queue:?} has an invalid deployment reference"
        );
    }
    Ok(())
}

/// The normalized push-consumer settings stored in a deployment manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueConsumerConfig {
    pub queue: String,
    pub max_batch_size: u16,
    pub max_batch_timeout: u16,
    pub max_retries: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_letter_queue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrency: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_delay: Option<u32>,
}

/// Validate every Queue value before a deployment becomes runtime state.
///
/// A native deploy validates its source configuration before it writes a
/// manifest. A managed deploy has a separate TypeScript producer, so the node
/// repeats the authoritative checks from `celld-logic` when it loads either
/// manifest. This prevents a malformed producer from becoming a missing
/// binding and prevents an invalid consumer policy from reaching the broker.
#[doc(hidden)]
pub fn validate_queue_manifest(manifest: &Manifest) -> anyhow::Result<()> {
    let queue_bindings = manifest
        .raw_metadata
        .get("bindings")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|binding| binding.get("type").and_then(serde_json::Value::as_str) == Some("queue"))
        .collect::<Vec<_>>();
    if queue_bindings.is_empty() && manifest.queue_consumers.is_empty() {
        return Ok(());
    }

    anyhow::ensure!(
        manifest
            .required_features
            .iter()
            .any(|feature| feature == FEATURE_QUEUES_V1),
        "Queue deployment does not require {FEATURE_QUEUES_V1}"
    );
    anyhow::ensure!(
        manifest
            .do_classes
            .iter()
            .any(|class| class == celld_logic::queue::RESERVED_CLASS)
            && manifest
                .sqlite_classes
                .iter()
                .any(|class| class == celld_logic::queue::RESERVED_CLASS),
        "Queue deployment does not install the reserved SQLite Queue class"
    );

    for binding in queue_bindings {
        let environment = binding
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| valid_binding_name(name))
            .context("Queue binding has an invalid environment name")?;
        let queue = binding
            .get("queue")
            .and_then(serde_json::Value::as_str)
            .filter(|queue| celld_logic::cell::valid_cell_scope(queue))
            .with_context(|| format!("Queue binding {environment:?} has an invalid queue name"))?;
        let delivery_delay_seconds = match binding.get("delivery_delay") {
            None => 0,
            Some(value) => value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .with_context(|| {
                    format!("Queue binding {environment:?} has an invalid delivery_delay")
                })?,
        };
        celld_logic::queue::validate_config(&celld_logic::queue::QueueConfig {
            max_batch_size: celld_logic::queue::DEFAULT_MAX_BATCH_SIZE,
            max_batch_timeout_seconds: celld_logic::queue::DEFAULT_MAX_BATCH_TIMEOUT_SECONDS,
            max_retries: celld_logic::queue::DEFAULT_MAX_RETRIES,
            max_concurrency: None,
            delivery_delay_seconds,
            retry_delay_seconds: None,
        })
        .map_err(anyhow::Error::new)
        .with_context(|| format!("Queue binding {environment:?} for {queue:?} is invalid"))?;
    }

    anyhow::ensure!(
        manifest.queue_consumers.is_empty() || manifest.main_module.is_some(),
        "Queue consumer deployment has no Worker module"
    );
    let mut consumed = std::collections::BTreeSet::new();
    for consumer in &manifest.queue_consumers {
        anyhow::ensure!(
            celld_logic::cell::valid_cell_scope(&consumer.queue),
            "Queue consumer has an invalid queue name {:?}",
            consumer.queue
        );
        anyhow::ensure!(
            consumed.insert(&consumer.queue),
            "Queue consumer deployment repeats queue {:?}",
            consumer.queue
        );
        if let Some(dead_letter_queue) = &consumer.dead_letter_queue {
            anyhow::ensure!(
                celld_logic::cell::valid_cell_scope(dead_letter_queue)
                    && dead_letter_queue != &consumer.queue,
                "Queue consumer for {:?} has an invalid dead-letter queue {:?}",
                consumer.queue,
                dead_letter_queue
            );
        }
        celld_logic::queue::validate_config(&celld_logic::queue::QueueConfig {
            max_batch_size: consumer.max_batch_size,
            max_batch_timeout_seconds: consumer.max_batch_timeout,
            max_retries: consumer.max_retries,
            max_concurrency: consumer.max_concurrency,
            delivery_delay_seconds: 0,
            retry_delay_seconds: consumer.retry_delay,
        })
        .map_err(anyhow::Error::new)
        .with_context(|| format!("Queue consumer for {:?} is invalid", consumer.queue))?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SipManifestListener {
    pub protocol: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SipManifestConfig {
    pub domains: Vec<String>,
    pub listeners: Vec<SipManifestListener>,
    #[serde(default = "default_auto_100_trying")]
    pub auto_100_trying: bool,
}

fn default_auto_100_trying() -> bool {
    true
}

impl SipManifestConfig {
    pub fn to_logic_config(&self) -> anyhow::Result<celld_logic::sip::SipConfig> {
        let mut listeners = Vec::with_capacity(self.listeners.len());
        for l in &self.listeners {
            let protocol = celld_logic::sip::SipProtocol::from_str(&l.protocol)
                .ok_or_else(|| anyhow::anyhow!("unknown SIP listener protocol {:?}", l.protocol))?;
            listeners.push(celld_logic::sip::SipListenerConfig {
                protocol,
                port: l.port,
                cert: l.cert.clone(),
                key: l.key.clone(),
                path: l.path.clone(),
            });
        }
        Ok(celld_logic::sip::SipConfig {
            domains: self.domains.clone(),
            listeners,
            auto_100_trying: self.auto_100_trying,
        })
    }
}

pub fn validate_sip_manifest(manifest: &Manifest) -> anyhow::Result<()> {
    let Some(sip) = &manifest.sip else {
        return Ok(());
    };
    anyhow::ensure!(
        manifest
            .required_features
            .iter()
            .any(|f| f == FEATURE_SIP_V1),
        "SIP deployment does not require {FEATURE_SIP_V1}"
    );
    anyhow::ensure!(
        manifest.main_module.is_some(),
        "SIP deployment has no Worker module"
    );
    let logic_config = sip.to_logic_config()?;
    celld_logic::sip::validate_config(&logic_config)
        .map_err(|e| anyhow::anyhow!("invalid SIP configuration: {e}"))?;
    Ok(())
}

fn valid_binding_name(name: &str) -> bool {
    name.len() <= 128
        && name
            .chars()
            .next()
            .is_some_and(|value| value == '_' || value == '$' || value.is_ascii_alphabetic())
        && name
            .chars()
            .skip(1)
            .all(|value| value == '_' || value == '$' || value.is_ascii_alphanumeric())
}

/// Reject a manifest requiring any feature this build does not support. Both
/// load paths (control-plane deployments and fleet pointer loads) must apply
/// the same gate, so it lives here beside the feature list.
pub fn validate_required_features(required: &[String]) -> anyhow::Result<()> {
    for feature in required {
        if !SUPPORTED_DEPLOYMENT_FEATURES.contains(&feature.as_str()) {
            anyhow::bail!(
                "deployment requires feature {feature:?} this celld build does not support; upgrade celld"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleRef {
    pub name: String,
    pub bytes: usize,
    /// Full SHA-256 of this module's exact bytes, as lowercase hexadecimal.
    ///
    /// The loader also accepts the 16-character prefix written by celld and
    /// the managed control plane before full module digests were introduced.
    pub sha256: String,
    /// Absent means UTF-8 source: the main module is ESM, siblings become
    /// text modules. `wasm` bytes become a module whose default export is a
    /// compiled `WebAssembly.Module` (Wrangler's `CompiledWasm` rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<ModuleKind>,
}

impl ModuleRef {
    pub(crate) fn verify(&self, body: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(
            body.len() == self.bytes,
            "deployment module size mismatch for {:?}: expected {}, got {}",
            self.name,
            self.bytes,
            body.len()
        );
        anyhow::ensure!(
            matches!(self.sha256.len(), 16 | 64)
                && self
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "deployment module {:?} has an invalid SHA-256 digest",
            self.name
        );
        let actual = format!("{:x}", Sha256::digest(body));
        anyhow::ensure!(
            actual.starts_with(&self.sha256),
            "deployment module digest mismatch for {:?}: expected {}, got {}",
            self.name,
            self.sha256,
            actual
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModuleKind {
    Wasm,
}

/// Reference from a deploy manifest to its immutable, canonical asset index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetManifestRef {
    pub index: String,
    pub sha256: String,
    pub file_count: u32,
    pub total_bytes: u64,
}

/// `deploy/<script>/<version>/assets.json`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AssetIndex {
    pub schema_version: u32,
    pub entries: BTreeMap<String, AssetEntry>,
    pub config: AssetConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetEntry {
    /// Full SHA-256 of the exact response body, lowercase hexadecimal.
    pub sha256: String,
    pub bytes: u64,
    /// `None` means omit Content-Type, matching Wrangler's `application/null`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_handling: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_found_handling: Option<String>,
    #[serde(default)]
    pub run_worker_first: RunWorkerFirst,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirects: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_date: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compatibility_flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RunWorkerFirst {
    Bool(bool),
    Routes(Vec<String>),
}

impl Default for RunWorkerFirst {
    fn default() -> Self {
        Self::Bool(false)
    }
}

/// A fleet-wide immutable asset body key. The digest is validated before this
/// is called by the receiver and again by the applying node.
pub fn asset_blob_key(sha256: &str) -> Option<String> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(format!(
        "deploy-blobs/assets/sha256/{}/{}",
        &sha256[..2],
        sha256
    ))
}

/// `deploy/current.json` — the fleet-wide pointer a node reads on startup.
/// Changing this is a deploy; nodes converge to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployPointer {
    /// Present on fleet-wide pointers. Older named pointers omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_name: Option<String>,
    pub version: String,
    pub prefix: String,
    pub rollout: Rollout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rollout {
    pub percent: u8,
}

/// Deployment identity: sorted module contents plus the serialized metadata,
/// never the raw upload framing (which is not deterministic). Every sender
/// must agree on this or identical code deploys as two versions depending on
/// the path used.
///
/// `metadata_json` is the exact byte serialization the sender stores as
/// `Manifest::raw_metadata`; callers pass the same bytes to both.
/// Cron trigger expressions are deliberately NOT an input. A version names
/// the code and its bindings; a schedule is configuration layered on top,
/// which is also how Cloudflare models it — schedules are their own resource,
/// set by their own API call after the script upload. Hashing them would make
/// the native and managed paths disagree about what a version is.
pub fn deployment_version(
    modules: &[(String, Vec<u8>)],
    metadata_json: &[u8],
    asset_index: Option<&[u8]>,
) -> String {
    let mut sorted = modules.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = Sha256::new();
    for (name, bytes) in sorted {
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
    }
    hasher.update(metadata_json);
    if let Some(index) = asset_index {
        hasher.update([0]);
        hasher.update(b"assets.json");
        hasher.update([0]);
        hasher.update(index);
    }
    format!("{:x}", hasher.finalize())[..16].to_string()
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use celld_logic::sip::{SipConfig, SipListenerConfig, SipProtocol};

    #[test]
    fn test_sip_logic_validate_config_valid() {
        let config = SipConfig {
            domains: vec!["sip.example.com".to_string(), "pbx.internal".to_string()],
            listeners: vec![
                SipListenerConfig {
                    protocol: SipProtocol::Udp,
                    port: 5060,
                    cert: None,
                    key: None,
                    path: None,
                },
                SipListenerConfig {
                    protocol: SipProtocol::Tcp,
                    port: 5060,
                    cert: None,
                    key: None,
                    path: None,
                },
                SipListenerConfig {
                    protocol: SipProtocol::Tls,
                    port: 5061,
                    cert: Some("./certs/fullchain.pem".to_string()),
                    key: Some("./certs/privkey.pem".to_string()),
                    path: None,
                },
                SipListenerConfig {
                    protocol: SipProtocol::Ws,
                    port: 8080,
                    cert: None,
                    key: None,
                    path: Some("/sip".to_string()),
                },
            ],
            auto_100_trying: true,
        };

        assert!(celld_logic::sip::validate_config(&config).is_ok());
    }

    #[test]
    fn test_sip_logic_validate_config_invalid_domain() {
        let mut config = SipConfig {
            domains: vec!["999.1.1.1".to_string()],
            listeners: vec![SipListenerConfig {
                protocol: SipProtocol::Udp,
                port: 5060,
                cert: None,
                key: None,
                path: None,
            }],
            auto_100_trying: true,
        };
        let err = celld_logic::sip::validate_config(&config).unwrap_err();
        assert_eq!(err.field, "domains");

        config.domains = vec![];
        let err = celld_logic::sip::validate_config(&config).unwrap_err();
        assert_eq!(err.field, "domains");
    }

    #[test]
    fn test_sip_logic_validate_config_invalid_listeners() {
        // Empty listeners
        let mut config = SipConfig {
            domains: vec!["sip.example.com".to_string()],
            listeners: vec![],
            auto_100_trying: true,
        };
        assert_eq!(
            celld_logic::sip::validate_config(&config).unwrap_err().field,
            "listeners"
        );

        // Port 0
        config.listeners = vec![SipListenerConfig {
            protocol: SipProtocol::Udp,
            port: 0,
            cert: None,
            key: None,
            path: None,
        }];
        assert_eq!(
            celld_logic::sip::validate_config(&config).unwrap_err().field,
            "listeners.port"
        );

        // Duplicate listener
        config.listeners = vec![
            SipListenerConfig {
                protocol: SipProtocol::Udp,
                port: 5060,
                cert: None,
                key: None,
                path: None,
            },
            SipListenerConfig {
                protocol: SipProtocol::Udp,
                port: 5060,
                cert: None,
                key: None,
                path: None,
            },
        ];
        assert_eq!(
            celld_logic::sip::validate_config(&config).unwrap_err().field,
            "listeners"
        );

        // TLS missing cert or key
        config.listeners = vec![SipListenerConfig {
            protocol: SipProtocol::Tls,
            port: 5061,
            cert: None,
            key: Some("key.pem".into()),
            path: None,
        }];
        assert_eq!(
            celld_logic::sip::validate_config(&config).unwrap_err().field,
            "listeners.cert"
        );

        // WS invalid path
        config.listeners = vec![SipListenerConfig {
            protocol: SipProtocol::Ws,
            port: 8080,
            cert: None,
            key: None,
            path: Some("sip_no_slash".into()),
        }];
        assert_eq!(
            celld_logic::sip::validate_config(&config).unwrap_err().field,
            "listeners.path"
        );
    }

    #[test]
    fn test_validate_sip_manifest_gate() {
        let valid_sip = SipManifestConfig {
            domains: vec!["sip.example.com".to_string()],
            listeners: vec![SipManifestListener {
                protocol: "udp".to_string(),
                port: 5060,
                cert: None,
                key: None,
                path: None,
            }],
            auto_100_trying: true,
        };

        let mut manifest = Manifest {
            schema_version: 1,
            version: "v1".to_string(),
            script_name: "test-sip".to_string(),
            main_module: Some("index.js".to_string()),
            do_classes: vec![],
            sqlite_classes: vec![],
            modules: vec![],
            assets: None,
            crons: vec![],
            queue_consumers: vec![],
            containers: vec![],
            fence_image: None,
            sip: Some(valid_sip.clone()),
            required_features: vec![FEATURE_SIP_V1.to_string()],
            raw_metadata: serde_json::json!({}),
        };

        // Fully valid manifest
        assert!(validate_sip_manifest(&manifest).is_ok());

        // Missing FEATURE_SIP_V1 in required_features
        manifest.required_features = vec![];
        let err = validate_sip_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("does not require sip-v1"));

        // Missing main_module
        manifest.required_features = vec![FEATURE_SIP_V1.to_string()];
        manifest.main_module = None;
        let err = validate_sip_manifest(&manifest).unwrap_err();
        assert!(err.to_string().contains("has no Worker module"));

        // Manifest with no SIP config passes
        manifest.sip = None;
        assert!(validate_sip_manifest(&manifest).is_ok());
    }

    struct RealDigestHasher;
    impl celld_logic::sip::DigestHasher for RealDigestHasher {
        fn hash_md5_hex(&self, data: &[u8]) -> String {
            use md5::{Digest, Md5};
            format!("{:x}", Md5::digest(data))
        }
        fn hash_sha256_hex(&self, data: &[u8]) -> String {
            use sha2::{Digest, Sha256};
            format!("{:x}", Sha256::digest(data))
        }
    }

    #[test]
    fn test_sip_parse_and_serialize_invite() {
        use celld_logic::sip::{parse_sip_message, SipMessage, SipProtocol, SipTransportMeta};

        let raw = concat!(
            "INVITE sip:bob@sip.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKnashds7;rport\r\n",
            "Max-Forwards: 70\r\n",
            "From: \"Alice\" <sip:alice@sip.example.com>;tag=1928301774\r\n",
            "To: <sip:bob@sip.example.com>\r\n",
            "Call-ID: a84b4c76e66710\r\n",
            "CSeq: 314159 INVITE\r\n",
            "Contact: <sip:alice@192.0.2.1:5060;transport=udp>;expires=3600\r\n",
            "Content-Type: application/sdp\r\n",
            "X-Custom-Header: multi-line\r\n folded-value\r\n",
            "Content-Length: 14\r\n",
            "\r\n",
            "v=0\r\no=alice\r\n"
        );

        let transport = SipTransportMeta {
            protocol: SipProtocol::Udp,
            source_address: "192.0.2.1:5060".to_string(),
            destination_address: Some("192.0.2.200:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: Some("udp-5060".to_string()),
        };

        let (msg, consumed) = parse_sip_message(raw.as_bytes(), transport.clone())
            .unwrap()
            .expect("must parse full message");
        assert_eq!(consumed, raw.len());

        let req = match msg {
            SipMessage::Request(r) => r,
            SipMessage::Response(_) => panic!("expected request"),
        };

        assert_eq!(req.method, "INVITE");
        assert_eq!(req.uri.user_at_host(), "bob@sip.example.com");
        assert_eq!(req.call_id, "a84b4c76e66710");
        assert_eq!(req.cseq, (314159, "INVITE".to_string()));
        assert_eq!(req.from.display_name.as_deref(), Some("Alice"));
        assert_eq!(req.from.tag.as_deref(), Some("1928301774"));
        assert_eq!(req.contacts.len(), 1);
        assert_eq!(req.contacts[0].expires, Some(3600));
        assert_eq!(req.body, b"v=0\r\no=alice\r\n");

        // Verify folded header was unfolded
        let custom = req.headers.iter().find(|(k, _)| k == "X-Custom-Header");
        assert!(custom.is_some());
        assert_eq!(custom.unwrap().1, "multi-line folded-value");

        // Verify round-trip serialization
        let serialized = req.serialize();
        let (re_parsed, _) = parse_sip_message(&serialized, transport)
            .unwrap()
            .expect("must re-parse serialized request");
        if let SipMessage::Request(re_req) = re_parsed {
            assert_eq!(re_req.method, req.method);
            assert_eq!(re_req.uri.to_string(), req.uri.to_string());
            assert_eq!(re_req.call_id, req.call_id);
            assert_eq!(re_req.cseq, req.cseq);
            assert_eq!(re_req.body, req.body);
        } else {
            panic!("expected request");
        }
    }

    #[test]
    fn test_sip_compact_headers_parsing() {
        use celld_logic::sip::{parse_sip_message, SipMessage, SipProtocol, SipTransportMeta};

        let raw = concat!(
            "REGISTER sip:sip.example.com SIP/2.0\r\n",
            "v: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bKreg1\r\n",
            "f: <sip:alice@sip.example.com>;tag=tag1\r\n",
            "t: <sip:alice@sip.example.com>\r\n",
            "i: call-id-xyz\r\n",
            "CSeq: 1 REGISTER\r\n",
            "m: <sip:alice@192.0.2.1:5060>;expires=600\r\n",
            "l: 0\r\n",
            "\r\n"
        );

        let transport = SipTransportMeta {
            protocol: SipProtocol::Tcp,
            source_address: "192.0.2.1:5060".to_string(),
            destination_address: None,
            node_id: "node-1".to_string(),
            listener_id: None,
        };

        let (msg, _) = parse_sip_message(raw.as_bytes(), transport)
            .unwrap()
            .expect("must parse");
        if let SipMessage::Request(req) = msg {
            assert_eq!(req.method, "REGISTER");
            assert_eq!(req.vias.len(), 1);
            assert_eq!(req.vias[0].transport, SipProtocol::Tcp);
            assert_eq!(req.call_id, "call-id-xyz");
            assert_eq!(req.contacts.len(), 1);
            assert_eq!(req.contacts[0].expires, Some(600));
        } else {
            panic!("expected request");
        }
    }

    #[test]
    fn test_sip_digest_auth_verification() {
        use celld_logic::sip::{
            format_digest_challenge, verify_digest, DigestAlgorithm, DigestCredentials,
            DigestVerdict,
        };

        let challenge = format_digest_challenge("sip.example.com", "nonce12345", DigestAlgorithm::Md5, false);
        assert!(challenge.contains("realm=\"sip.example.com\""));
        assert!(challenge.contains("nonce=\"nonce12345\""));
        assert!(challenge.contains("algorithm=MD5"));

        let hasher = RealDigestHasher;
        // Known test vector:
        // username = "alice", realm = "sip.example.com", password = "secretpassword"
        // HA1 = MD5("alice:sip.example.com:secretpassword") = MD5("alice:sip.example.com:secretpassword")
        use md5::{Digest, Md5};
        let ha1_hex = format!("{:x}", Md5::digest(b"alice:sip.example.com:secretpassword"));

        let auth_hdr = concat!(
            "Digest username=\"alice\", realm=\"sip.example.com\", nonce=\"nonce12345\", ",
            "uri=\"sip:sip.example.com\", qop=auth, nc=00000001, cnonce=\"c123\", ",
            "response=\"\"" // will compute response below
        );

        // Compute correct response for test
        // HA2 = MD5("REGISTER:sip:sip.example.com")
        let ha2_hex = format!("{:x}", Md5::digest(b"REGISTER:sip:sip.example.com"));
        // Response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
        let resp_input = format!("{ha1_hex}:nonce12345:00000001:c123:auth:{ha2_hex}");
        let correct_resp = format!("{:x}", Md5::digest(resp_input.as_bytes()));

        let auth_hdr_valid = auth_hdr.replace("response=\"\"", &format!("response=\"{correct_resp}\""));
        let creds = DigestCredentials::parse(&auth_hdr_valid).expect("must parse credentials");

        let verdict = verify_digest(&creds, "REGISTER", &ha1_hex, &hasher);
        assert_eq!(verdict, DigestVerdict::Verified);

        // Wrong password hash
        let verdict_wrong = verify_digest(&creds, "REGISTER", "00112233445566778899aabbccddeeff", &hasher);
        assert_eq!(verdict_wrong, DigestVerdict::InvalidResponse);
    }

    #[test]
    fn test_sip_transaction_state_machine_invite_retransmission_and_ack() {
        use celld_logic::sip::{
            parse_sip_message, SipAction, SipMessage, SipProtocol, SipResponseData, SipTimerKind,
            SipTransactionTable, SipTransportMeta,
        };

        let raw_invite = concat!(
            "INVITE sip:bob@sip.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKtxn123\r\n",
            "From: <sip:alice@sip.example.com>;tag=from1\r\n",
            "To: <sip:bob@sip.example.com>\r\n",
            "Call-ID: call-123\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );

        let transport = SipTransportMeta {
            protocol: SipProtocol::Udp,
            source_address: "192.0.2.1:5060".to_string(),
            destination_address: Some("192.0.2.200:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: None,
        };

        let mut tx_table = SipTransactionTable::new();
        let (msg1, _) = parse_sip_message(raw_invite.as_bytes(), transport.clone())
            .unwrap()
            .unwrap();

        // 1. Initial INVITE packet arrived
        let actions = tx_table.handle_incoming(msg1, 1000, true);
        assert_eq!(actions.len(), 2);
        // Action 0: 100 Trying wire send
        match &actions[0] {
            SipAction::SendWire { bytes, .. } => {
                let wire = String::from_utf8_lossy(bytes);
                assert!(wire.contains("100 Trying"));
            }
            _ => panic!("expected SendWire 100 Trying"),
        }
        // Action 1: Deliver to Worker
        let tx_id = match &actions[1] {
            SipAction::DeliverRequestToWorker { tx_id, request } => {
                assert_eq!(request.method, "INVITE");
                *tx_id
            }
            _ => panic!("expected DeliverRequestToWorker"),
        };

        // 2. Client retransmits INVITE before Worker answered (packet retransmission)
        let (msg2, _) = parse_sip_message(raw_invite.as_bytes(), transport.clone())
            .unwrap()
            .unwrap();
        let retransmit_actions = tx_table.handle_incoming(msg2, 1200, true);
        assert_eq!(retransmit_actions.len(), 1);
        match &retransmit_actions[0] {
            SipAction::SendWire { bytes, .. } => {
                let wire = String::from_utf8_lossy(bytes);
                assert!(wire.contains("100 Trying"));
            }
            _ => panic!("expected retransmitted provisional response"),
        }
        // Crucial invariant: Worker is NOT invoked again!

        // 3. Worker emits provisional 180 Ringing
        let (req_parsed, _) = parse_sip_message(raw_invite.as_bytes(), transport.clone())
            .unwrap()
            .unwrap();
        let req_data = match req_parsed {
            SipMessage::Request(r) => r,
            _ => panic!(),
        };
        let ringing = SipResponseData {
            status: 180,
            reason: "Ringing".to_string(),
            version: "SIP/2.0".to_string(),
            vias: req_data.vias.clone(),
            from: req_data.from.clone(),
            to: req_data.to.clone(),
            call_id: req_data.call_id.clone(),
            cseq: req_data.cseq.clone(),
            contacts: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let prov_actions = tx_table.handle_worker_response(tx_id, ringing, 1300);
        assert_eq!(prov_actions.len(), 1);
        match &prov_actions[0] {
            SipAction::SendWire { bytes, .. } => {
                assert!(String::from_utf8_lossy(bytes).contains("180 Ringing"));
            }
            _ => panic!("expected SendWire 180 Ringing"),
        }

        // 4. Duplicate INVITE now receives 180 Ringing!
        let (msg3, _) = parse_sip_message(raw_invite.as_bytes(), transport.clone())
            .unwrap()
            .unwrap();
        let retrans3 = tx_table.handle_incoming(msg3, 1400, true);
        assert_eq!(retrans3.len(), 1);
        match &retrans3[0] {
            SipAction::SendWire { bytes, .. } => {
                assert!(String::from_utf8_lossy(bytes).contains("180 Ringing"));
            }
            _ => panic!("expected retransmitted 180 Ringing"),
        }

        // 5. Worker emits final 486 Busy Here
        let busy = SipResponseData {
            status: 486,
            reason: "Busy Here".to_string(),
            version: "SIP/2.0".to_string(),
            vias: req_data.vias.clone(),
            from: req_data.from.clone(),
            to: req_data.to.clone(),
            call_id: req_data.call_id.clone(),
            cseq: req_data.cseq.clone(),
            contacts: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let busy_actions = tx_table.handle_worker_response(tx_id, busy, 1500);
        // Emits SendWire(486) + ArmTimer(TimerG) + ArmTimer(TimerH)
        assert_eq!(busy_actions.len(), 3);

        // 6. ACK arrives for 486: transitions to Confirmed
        let raw_ack = concat!(
            "ACK sip:bob@sip.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKtxn123\r\n",
            "From: <sip:alice@sip.example.com>;tag=from1\r\n",
            "To: <sip:bob@sip.example.com>\r\n",
            "Call-ID: call-123\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        let (ack_msg, _) = parse_sip_message(raw_ack.as_bytes(), transport.clone())
            .unwrap()
            .unwrap();
        let ack_actions = tx_table.handle_incoming(ack_msg, 1600, true);
        assert_eq!(ack_actions.len(), 1);
        match &ack_actions[0] {
            SipAction::ArmTimer { timer, .. } => {
                assert_eq!(*timer, SipTimerKind::TimerI);
            }
            _ => panic!("expected Timer I armed for Confirmed state"),
        }
    }

    #[test]
    fn test_sip_transaction_client_forking_auto_ack() {
        use celld_logic::sip::{
            SipAction, SipMessage, SipProtocol, SipRequestData, SipResponseData,
            SipTransactionTable, SipTransportMeta, SipUri, SipVia,
        };

        let mut tx_table = SipTransactionTable::new();
        let req = SipRequestData {
            method: "INVITE".to_string(),
            uri: SipUri::parse("sip:target@192.0.2.50:5060").unwrap(),
            version: "SIP/2.0".to_string(),
            vias: vec![SipVia {
                version: "SIP/2.0".to_string(),
                transport: SipProtocol::Udp,
                sent_by: "edge.celld:5060".to_string(),
                branch: Some("z9hG4bKclient_fork_1".to_string()),
                received: None,
                rport: None,
                params: std::collections::BTreeMap::new(),
            }],
            from: celld_logic::sip::SipNameAddr::parse("<sip:caller@sip.example.com>;tag=t1").unwrap(),
            to: celld_logic::sip::SipNameAddr::parse("<sip:target@sip.example.com>").unwrap(),
            call_id: "client-call-1".to_string(),
            cseq: (1, "INVITE".to_string()),
            contacts: Vec::new(),
            max_forwards: 70,
            expires: None,
            headers: Vec::new(),
            body: Vec::new(),
            transport: SipTransportMeta {
                protocol: SipProtocol::Udp,
                source_address: "192.0.2.10:5060".to_string(),
                destination_address: Some("192.0.2.50:5060".to_string()),
                node_id: "node-1".to_string(),
                listener_id: None,
            },
        };

        let (tx_id, start_actions) = tx_table.start_client_transaction(req.clone(), "192.0.2.50:5060".to_string(), 1000);
        assert_eq!(start_actions.len(), 3); // SendWire + TimerA + TimerB

        // Target responds with 486 Busy Here
        let resp_486 = SipResponseData {
            status: 486,
            reason: "Busy Here".to_string(),
            version: "SIP/2.0".to_string(),
            vias: req.vias.clone(),
            from: req.from.clone(),
            to: req.to.clone(),
            call_id: req.call_id.clone(),
            cseq: req.cseq.clone(),
            contacts: Vec::new(),
            headers: Vec::new(),
            body: Vec::new(),
        };

        let actions = tx_table.handle_incoming(SipMessage::Response(resp_486), 1200, true);
        // Client transaction must auto-send ACK on wire, deliver 486 to client, and arm Timer D
        assert_eq!(actions.len(), 3);

        match &actions[0] {
            SipAction::SendWire { bytes, .. } => {
                let wire = String::from_utf8_lossy(bytes);
                assert!(wire.starts_with("ACK "));
                assert!(wire.contains("CSeq: 1 ACK"));
            }
            _ => panic!("expected automatic ACK transmission"),
        }

        match &actions[1] {
            SipAction::DeliverResponseToClient { tx_id: id, response } => {
                assert_eq!(*id, tx_id);
                assert_eq!(response.status, 486);
            }
            _ => panic!("expected DeliverResponseToClient"),
        }
    }

    #[tokio::test]
    async fn test_sip_worker_options_and_js_surface() {
        use crate::engine_api::{RuntimeSipRequest, WorkerConfigOptions};
        use crate::js::Worker;
        use crate::WorkerJob;

        let script = r#"
            export default {
                async sip(req, env, ctx) {
                    if (req.method === "OPTIONS") {
                        if (req.uri.userAtHost !== "server@example.com") {
                            return new SipResponse(400, "Bad Request");
                        }
                        return new SipResponse(200, "OK", {
                            headers: [["Allow", "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER"]]
                        });
                    }
                    return new SipResponse(405, "Method Not Allowed");
                }
            };
        "#;

        let options = WorkerConfigOptions {
            src: script.to_string(),
            ..Default::default()
        };
        let mut worker = Worker::load(options).expect("Worker should load");

        let req = RuntimeSipRequest {
            id: 1001,
            method: "OPTIONS".to_string(),
            uri: "sip:server@example.com".to_string(),
            version: "SIP/2.0".to_string(),
            headers: vec![("Call-ID".to_string(), "opt-1".to_string())],
            body: Vec::new(),
            transport_protocol: "udp".to_string(),
            source_address: "192.0.2.10:5060".to_string(),
            destination_address: Some("192.0.2.1:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: Some("udp-5060".to_string()),
            call_id: "opt-1".to_string(),
            cseq_num: 1,
            cseq_method: "OPTIONS".to_string(),
            from: "<sip:alice@example.com>;tag=from-1".to_string(),
            to: "<sip:server@example.com>".to_string(),
            contacts: Vec::new(),
            max_forwards: 70,
            expires: None,
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let job = WorkerJob::Sip {
            queued_at: std::time::Instant::now(),
            entrypoint: None,
            request: Box::new(req),
            provisional_sender: None,
            reply: reply_tx,
        };

        let (_begun, _) = worker.turn_begin(job, None);
        let resp = reply_rx.await.unwrap().expect("handler answered response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        let allow = resp.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Allow"));
        assert!(allow.is_some());
        assert_eq!(allow.unwrap().1, "INVITE, ACK, CANCEL, BYE, OPTIONS, REGISTER");
    }

    #[tokio::test]
    async fn test_sip_worker_provisional_response_and_final_response() {
        use crate::engine_api::{RuntimeSipRequest, WorkerConfigOptions};
        use crate::js::Worker;
        use crate::WorkerJob;

        let script = r#"
            export default {
                async sip(req, env, ctx) {
                    if (req.method === "INVITE") {
                        req.sendProvisional(180, "Ringing");
                        return new SipResponse(200, "OK", {
                            headers: [["Content-Type", "application/sdp"]],
                            body: "v=0\r\no=bob\r\n"
                        });
                    }
                    return new SipResponse(400, "Bad Request");
                }
            };
        "#;

        let options = WorkerConfigOptions {
            src: script.to_string(),
            ..Default::default()
        };
        let mut worker = Worker::load(options).expect("Worker should load");

        let req = RuntimeSipRequest {
            id: 2002,
            method: "INVITE".to_string(),
            uri: "sip:bob@example.com".to_string(),
            version: "SIP/2.0".to_string(),
            headers: vec![("Call-ID".to_string(), "inv-1".to_string())],
            body: b"v=0\r\no=alice\r\n".to_vec(),
            transport_protocol: "udp".to_string(),
            source_address: "192.0.2.10:5060".to_string(),
            destination_address: Some("192.0.2.1:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: Some("udp-5060".to_string()),
            call_id: "inv-1".to_string(),
            cseq_num: 1,
            cseq_method: "INVITE".to_string(),
            from: "<sip:alice@example.com>;tag=from-1".to_string(),
            to: "<sip:bob@example.com>".to_string(),
            contacts: vec!["<sip:alice@192.0.2.10:5060>".to_string()],
            max_forwards: 70,
            expires: None,
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let (prov_tx, mut prov_rx) = tokio::sync::mpsc::unbounded_channel();
        let job = WorkerJob::Sip {
            queued_at: std::time::Instant::now(),
            entrypoint: None,
            request: Box::new(req),
            provisional_sender: Some(prov_tx),
            reply: reply_tx,
        };

        let (_begun, _) = worker.turn_begin(job, None);
        let resp = reply_rx.await.unwrap().expect("handler answered response");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.reason, "OK");
        assert_eq!(resp.body, b"v=0\r\no=bob\r\n");

        // Verify provisional response was sent
        let prov = prov_rx.try_recv().expect("must have received provisional response");
        assert_eq!(prov.status, 180);
        assert_eq!(prov.reason, "Ringing");
    }

    #[tokio::test]
    async fn test_sip_worker_digest_auth_verification() {
        use crate::engine_api::{RuntimeSipRequest, WorkerConfigOptions};
        use crate::js::Worker;
        use crate::WorkerJob;

        let script = r#"
            export default {
                async sip(req, env, ctx) {
                    const auth = req.verifyDigestAuth({
                        realm: "sip.example.com",
                        password: "supersecretpassword",
                    });
                    if (!auth.verified) {
                        return auth.challengeResponse(401);
                    }
                    return new SipResponse(200, "OK", {
                        headers: [["X-Authenticated-User", auth.username]]
                    });
                }
            };
        "#;

        let options = WorkerConfigOptions {
            src: script.to_string(),
            ..Default::default()
        };
        let mut worker = Worker::load(options).expect("Worker should load");

        // Step 1: Unauthenticated request -> expect 401
        let req_unauth = RuntimeSipRequest {
            id: 3001,
            method: "REGISTER".to_string(),
            uri: "sip:sip.example.com".to_string(),
            version: "SIP/2.0".to_string(),
            headers: vec![("Call-ID".to_string(), "reg-1".to_string())],
            body: Vec::new(),
            transport_protocol: "udp".to_string(),
            source_address: "192.0.2.10:5060".to_string(),
            destination_address: Some("192.0.2.1:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: Some("udp-5060".to_string()),
            call_id: "reg-1".to_string(),
            cseq_num: 1,
            cseq_method: "REGISTER".to_string(),
            from: "<sip:alice@sip.example.com>;tag=from-1".to_string(),
            to: "<sip:alice@sip.example.com>".to_string(),
            contacts: vec!["<sip:alice@192.0.2.10:5060>".to_string()],
            max_forwards: 70,
            expires: Some(3600),
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let job = WorkerJob::Sip {
            queued_at: std::time::Instant::now(),
            entrypoint: None,
            request: Box::new(req_unauth),
            provisional_sender: None,
            reply: reply_tx,
        };
        let (_begun, _) = worker.turn_begin(job, None);
        let resp_unauth = reply_rx.await.unwrap().expect("401 challenge");
        assert_eq!(resp_unauth.status, 401);
        let www_auth = resp_unauth.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("WWW-Authenticate"));
        assert!(www_auth.is_some());
        let challenge = &www_auth.unwrap().1;
        assert!(challenge.contains("realm=\"sip.example.com\""));
        assert!(challenge.contains("nonce="));

        // Extract nonce from challenge
        let nonce = challenge
            .split("nonce=\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("nonce in challenge");

        // Step 2: Compute valid response for user "alice", password "supersecretpassword"
        use md5::{Digest, Md5};
        let ha1 = format!("{:x}", Md5::digest(b"alice:sip.example.com:supersecretpassword"));
        let ha2 = format!("{:x}", Md5::digest(b"REGISTER:sip:sip.example.com"));
        let resp_input = format!("{ha1}:{nonce}:00000001:c123:auth:{ha2}");
        let response_hex = format!("{:x}", Md5::digest(resp_input.as_bytes()));

        let auth_hdr = format!(
            "Digest username=\"alice\", realm=\"sip.example.com\", nonce=\"{nonce}\", uri=\"sip:sip.example.com\", qop=auth, nc=00000001, cnonce=\"c123\", response=\"{response_hex}\""
        );

        let req_auth = RuntimeSipRequest {
            id: 3002,
            method: "REGISTER".to_string(),
            uri: "sip:sip.example.com".to_string(),
            version: "SIP/2.0".to_string(),
            headers: vec![
                ("Call-ID".to_string(), "reg-1".to_string()),
                ("Authorization".to_string(), auth_hdr),
            ],
            body: Vec::new(),
            transport_protocol: "udp".to_string(),
            source_address: "192.0.2.10:5060".to_string(),
            destination_address: Some("192.0.2.1:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: Some("udp-5060".to_string()),
            call_id: "reg-1".to_string(),
            cseq_num: 2,
            cseq_method: "REGISTER".to_string(),
            from: "<sip:alice@sip.example.com>;tag=from-1".to_string(),
            to: "<sip:alice@sip.example.com>".to_string(),
            contacts: vec!["<sip:alice@192.0.2.10:5060>".to_string()],
            max_forwards: 70,
            expires: Some(3600),
        };

        let (reply_tx2, reply_rx2) = tokio::sync::oneshot::channel();
        let job2 = WorkerJob::Sip {
            queued_at: std::time::Instant::now(),
            entrypoint: None,
            request: Box::new(req_auth),
            provisional_sender: None,
            reply: reply_tx2,
        };
        let (_begun2, _) = worker.turn_begin(job2, None);
        let resp_auth = reply_rx2.await.unwrap().expect("200 OK after auth");
        assert_eq!(resp_auth.status, 200);
        let auth_user = resp_auth.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("X-Authenticated-User"));
        assert!(auth_user.is_some());
        assert_eq!(auth_user.unwrap().1, "alice");
    }

    #[test]
    fn test_sip_output_gate_durability_and_lease_fence() {
        use celld_logic::{
            on_event, Channel, Config, Effect, Event, HaltReason, LeaseCasOutcome,
            NodeLeaseSpec, OwnershipOnEvict, ProofSource,
            RequestError, State, Timer,
        };

        let config = Config {
            max_resident: 10,
            max_activations: 5,
            max_evictions: 2,
            max_releases: 2,
            alarm_resident_ms: 0,
            require_node_lease: true,
            peer_protocol: 1,
            operation_deadline_ms: Some(10_000),
            owner_log_recovery_backoff_ms: 1_000,
            owner_log_recovery_attempts: 3,
            idle_evict_ms: None,
            pressure: celld_logic::pressure::PressureConfig::default(),
            max_outbound_websockets: 5,
            ownership_on_evict: OwnershipOnEvict::Sticky,
        };

        let mut state = State::new("node-1", config);

        // 1. Establish Node Lease
        let spec = NodeLeaseSpec {
            addr: "127.0.0.1:8080".to_string(),
            peer_protocol: 1,
            generation: "gen-1".to_string(),
            resume_generation: None,
            ttl_ms: 5000,
        };
        let effects = on_event(
            &mut state,
            Event::StartNodeLease {
                now_ms: 1000,
                now_mono_ms: 1000,
                spec: spec.clone(),
            },
        );
        let read_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::ReadSelfNodeLease { op } => Some(*op),
                _ => None,
            })
            .expect("read self node lease");

        let effects = on_event(
            &mut state,
            Event::SelfNodeLeaseRead {
                op: read_op,
                now_ms: 1000,
                now_mono_ms: 1000,
                result: Ok(None),
            },
        );
        let cas_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::CasNodeLease { op, .. } => Some(*op),
                _ => None,
            })
            .expect("cas node lease");

        let effects = on_event(
            &mut state,
            Event::NodeLeaseCasCompleted {
                op: cas_op,
                now_mono_ms: 1000,
                result: Ok(LeaseCasOutcome::Applied {
                    etag: "lease-etag-1".to_string(),
                }),
                stamped_log_state: None,
            },
        );
        assert!(effects.iter().any(|e| matches!(e, Effect::ScheduleTimer { timer: Timer::NodeLeaseFence { generation: 1 }, .. })));

        let _ = on_event(
            &mut state,
            Event::LocalCellsRead {
                result: Ok(Vec::new()),
            },
        );

        // 2. Bring Cell to Resident
        let effects = on_event(
            &mut state,
            Event::RequestAt {
                request: 101,
                cell: "sip-call-1".to_string(),
                now_mono_ms: 1000,
            },
        );
        let owner_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::ReadOwner { op, .. } => Some(*op),
                _ => None,
            })
            .expect("read owner");

        let effects = on_event(
            &mut state,
            Event::OwnerRead {
                op: owner_op,
                now_ms: 1000,
                result: Ok(None),
            },
        );
        let cas_owner_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::CasOwner { op, .. } => Some(*op),
                _ => None,
            })
            .expect("cas owner");

        let effects = on_event(
            &mut state,
            Event::OwnerCasCompleted {
                op: cas_owner_op,
                result: Ok(celld_logic::CasOutcome::Applied),
            },
        );
        let restore_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::Restore { op, .. } => Some(*op),
                _ => None,
            })
            .expect("restore");

        let effects = on_event(
            &mut state,
            Event::RestoreCompleted {
                op: restore_op,
                result: Ok(celld_logic::RestoreOutcome {
                    restored: true,
                    alarm: None,
                }),
            },
        );
        let start_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::StartRuntime { op, .. } => Some(*op),
                _ => None,
            })
            .expect("start runtime");

        let effects = on_event(
            &mut state,
            Event::RuntimeStarted {
                op: start_op,
                isolate: None,
                generation: 0,
                result: Ok(()),
            },
        );
        let publish_op = effects
            .iter()
            .find_map(|e| match e {
                Effect::Publish { op, .. } => Some(*op),
                _ => None,
            })
            .expect("publish");

        let effects = on_event(
            &mut state,
            Event::Published {
                op: publish_op,
                result: Ok(()),
            },
        );
        assert!(effects.iter().any(|e| matches!(e, Effect::Complete { request: 101, result: Ok(celld_logic::Route::Local) })));

        // 3. DO cell writes at position 1: emits Channel::Response and Channel::SipEgress
        let effects_resp = on_event(
            &mut state,
            Event::OutputAt {
                request: 101,
                channel: Channel::Response,
                position: Some(1),
                observed: None,
                epoch: Some(1),
                now_mono_ms: 1010,
            },
        );
        let await_op = effects_resp
            .iter()
            .find_map(|e| match e {
                Effect::AwaitDurable { op, position, .. } if *position == 1 => Some(*op),
                _ => None,
            })
            .expect("await durable at pos 1");
        // No release emitted yet for Response
        assert!(!effects_resp.iter().any(|e| matches!(e, Effect::Release { .. })));

        let effects_egress = on_event(
            &mut state,
            Event::OutputAt {
                request: 101,
                channel: Channel::SipEgress,
                position: None,
                observed: None,
                epoch: Some(1),
                now_mono_ms: 1010,
            },
        );
        // Egress trails the open barrier; no release emitted yet
        assert!(!effects_egress.iter().any(|e| matches!(e, Effect::Release { .. })));

        // 4. Durability proven for position 1: both tickets released!
        let effects_durable = on_event(
            &mut state,
            Event::DurableReached {
                op: await_op,
                result: Ok(1),
                source: ProofSource::Fleet,
            },
        );
        let mut released_resp = false;
        let mut released_egress = false;
        for effect in &effects_durable {
            if let Effect::Release { request, channel, result } = effect {
                assert_eq!(*request, 101);
                assert_eq!(*result, Ok(()));
                if *channel == Channel::Response {
                    released_resp = true;
                } else if *channel == Channel::SipEgress {
                    released_egress = true;
                }
            }
        }
        assert!(released_resp, "Channel::Response must be released upon DurabilityReached");
        assert!(released_egress, "Channel::SipEgress must be released upon DurabilityReached");

        // 5. DO cell writes at position 2: again both tickets withheld
        let effects_resp2 = on_event(
            &mut state,
            Event::OutputAt {
                request: 101,
                channel: Channel::Response,
                position: Some(2),
                observed: None,
                epoch: Some(1),
                now_mono_ms: 1020,
            },
        );
        assert!(effects_resp2.iter().any(|e| matches!(e, Effect::AwaitDurable { position: 2, .. })));

        let effects_egress2 = on_event(
            &mut state,
            Event::OutputAt {
                request: 101,
                channel: Channel::SipEgress,
                position: None,
                observed: None,
                epoch: Some(1),
                now_mono_ms: 1020,
            },
        );
        assert!(!effects_egress2.iter().any(|e| matches!(e, Effect::Release { .. })));

        // 6. Node lease expires -> Timer::NodeLeaseFence fires -> Channel::SipEgress & Channel::Response fail closed with RequestError::NodeFenced!
        let effects_fence = on_event(
            &mut state,
            Event::TimerFired {
                timer: Timer::NodeLeaseFence { generation: 1 },
                now_ms: 6000,
                now_mono_ms: 6000,
            },
        );

        let mut fenced_resp = false;
        let mut fenced_egress = false;
        for effect in &effects_fence {
            if let Effect::Release { request, channel, result } = effect {
                assert_eq!(*request, 101);
                assert_eq!(*result, Err(RequestError::NodeFenced));
                if *channel == Channel::Response {
                    fenced_resp = true;
                } else if *channel == Channel::SipEgress {
                    fenced_egress = true;
                }
            }
        }
        assert!(fenced_resp, "Channel::Response must fail closed with NodeFenced");
        assert!(fenced_egress, "Channel::SipEgress must fail closed with NodeFenced");
        assert!(effects_fence.iter().any(|e| matches!(e, Effect::Halt { reason: HaltReason::NodeLeaseExpired, .. })));
    }

    #[test]
    fn test_rtpengine_ng_bencode_codec() {
        use celld_logic::rtpengine::{
            parse_bencode, serialize_bencode, BencodeValue, RtpEngineCommandBuilder,
            RtpEngineMessage,
        };

        // 1. Primitive bencode parsing & serialization
        let int_val = BencodeValue::Int(42);
        let mut out = Vec::new();
        serialize_bencode(&int_val, &mut out);
        assert_eq!(out, b"i42e");
        assert_eq!(parse_bencode(&out).unwrap(), int_val);

        let str_val = BencodeValue::Bytes(b"hello world".to_vec());
        let mut out = Vec::new();
        serialize_bencode(&str_val, &mut out);
        assert_eq!(out, b"11:hello world");
        assert_eq!(parse_bencode(&out).unwrap(), str_val);

        let list_val = BencodeValue::List(vec![
            BencodeValue::Bytes(b"foo".to_vec()),
            BencodeValue::Int(123),
        ]);
        let mut out = Vec::new();
        serialize_bencode(&list_val, &mut out);
        assert_eq!(out, b"l3:fooi123ee");
        assert_eq!(parse_bencode(&out).unwrap(), list_val);

        // 2. rtpengine NG ping command
        let ping_msg = RtpEngineCommandBuilder::ping("cookie999");
        let serialized = ping_msg.serialize();
        assert_eq!(serialized, b"cookie999 d7:command4:pinge");

        let parsed = RtpEngineMessage::parse(&serialized).unwrap();
        assert_eq!(parsed.cookie, "cookie999");
        assert_eq!(parsed.payload.dict_get_str("command"), Some("ping"));

        // 3. rtpengine NG offer command with direction and sdp
        let sdp = "v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\ns=Call\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n";
        let offer_msg = RtpEngineCommandBuilder::offer(
            "c_offer_1",
            "call-xyz-123",
            "tag-alice-1",
            sdp,
            Some(("external", "internal")),
        );
        let offer_bytes = offer_msg.serialize();
        let parsed_offer = RtpEngineMessage::parse(&offer_bytes).unwrap();
        assert_eq!(parsed_offer.cookie, "c_offer_1");
        assert_eq!(parsed_offer.payload.dict_get_str("command"), Some("offer"));
        assert_eq!(parsed_offer.payload.dict_get_str("call-id"), Some("call-xyz-123"));
        assert_eq!(parsed_offer.payload.dict_get_str("from-tag"), Some("tag-alice-1"));
        assert_eq!(parsed_offer.payload.dict_get_str("sdp"), Some(sdp));
        let dir = parsed_offer.payload.dict_get("direction").unwrap().as_list().unwrap();
        assert_eq!(dir[0].as_str(), Some("external"));
        assert_eq!(dir[1].as_str(), Some("internal"));

        // 4. rtpengine NG response parsing (e.g. answer response from rtpengine)
        let raw_resp = b"c_offer_1 d6:result2:ok3:sdp28:v=0\r\nc=IN IP4 198.51.100.1\r\ne";
        let parsed_resp = RtpEngineMessage::parse(raw_resp).unwrap();
        assert_eq!(parsed_resp.cookie, "c_offer_1");
        assert_eq!(parsed_resp.payload.dict_get_str("result"), Some("ok"));
        assert_eq!(parsed_resp.payload.dict_get_str("sdp"), Some("v=0\r\nc=IN IP4 198.51.100.1\r\n"));

        // 5. rtpengine delete command
        let del_msg = RtpEngineCommandBuilder::delete(
            "c_del_1",
            "call-xyz-123",
            Some("tag-alice-1"),
            Some("tag-bob-1"),
        );
        let del_bytes = del_msg.serialize();
        let parsed_del = RtpEngineMessage::parse(&del_bytes).unwrap();
        assert_eq!(parsed_del.payload.dict_get_str("command"), Some("delete"));
        assert_eq!(parsed_del.payload.dict_get_str("to-tag"), Some("tag-bob-1"));
    }

    #[tokio::test]
    async fn test_rtpengine_client_integration() {
        use std::collections::BTreeMap;
        use std::net::SocketAddr;
        use tokio::net::UdpSocket;
        use celld_logic::rtpengine::{BencodeValue, RtpEngineMessage};
        use crate::sip_media::RtpEngineClient;

        // 1. Start mock rtpengine server
        let mock_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_sock.local_addr().unwrap();

        // Spawn mock rtpengine responder
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((len, src)) = mock_sock.recv_from(&mut buf).await {
                if let Ok(msg) = RtpEngineMessage::parse(&buf[..len]) {
                    let cmd = msg.payload.dict_get_str("command").unwrap_or("");
                    let mut dict = BTreeMap::new();
                    match cmd {
                        "ping" => {
                            dict.insert(b"result".to_vec(), BencodeValue::Bytes(b"pong".to_vec()));
                        }
                        "offer" => {
                            dict.insert(b"result".to_vec(), BencodeValue::Bytes(b"ok".to_vec()));
                            dict.insert(
                                b"sdp".to_vec(),
                                BencodeValue::Bytes(b"v=0\r\nc=IN IP4 198.51.100.99\r\n".to_vec()),
                            );
                        }
                        "delete" => {
                            dict.insert(b"result".to_vec(), BencodeValue::Bytes(b"ok".to_vec()));
                        }
                        _ => {
                            dict.insert(b"result".to_vec(), BencodeValue::Bytes(b"error".to_vec()));
                            dict.insert(
                                b"error-reason".to_vec(),
                                BencodeValue::Bytes(b"unsupported command".to_vec()),
                            );
                        }
                    }
                    let resp = RtpEngineMessage::new(msg.cookie, BencodeValue::Dict(dict));
                    let _ = mock_sock.send_to(&resp.serialize(), src).await;
                }
            }
        });

        // 2. Client binds and sends commands
        let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let client = RtpEngineClient::bind(mock_addr, client_bind).await.unwrap();

        // Ping
        client.ping().await.expect("ping should succeed");

        // Offer
        let rewritten_sdp = client
            .offer("call-test-1", "alice-tag", "v=0\r\nc=IN IP4 192.0.2.1\r\n", None)
            .await
            .expect("offer should succeed");
        assert_eq!(rewritten_sdp, "v=0\r\nc=IN IP4 198.51.100.99\r\n");

        // Delete
        client
            .delete("call-test-1", Some("alice-tag"), None)
            .await
            .expect("delete should succeed");
    }

    #[tokio::test]
    async fn test_sip_transport_udp_and_egress() {
        use tokio::net::UdpSocket;
        use crate::sip_transport::{send_egress, SipTransportServer};

        // 1. Bind transport server
        let server = SipTransportServer::bind_udp("test-node-1".to_string(), "127.0.0.1:0")
            .await
            .expect("bind udp server");
        let server_addr = server.udp_socket().unwrap().local_addr().unwrap();

        // 2. Client sends an INVITE packet to server
        let client_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_sock.local_addr().unwrap();

        let raw_invite = concat!(
            "INVITE sip:bob@sip.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKudp_trans_1\r\n",
            "From: <sip:alice@sip.example.com>;tag=from1\r\n",
            "To: <sip:bob@sip.example.com>\r\n",
            "Call-ID: call-trans-udp-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        client_sock.send_to(raw_invite.as_bytes(), server_addr).await.unwrap();

        // 3. Server receives and parses packet
        let (msg, src) = server.recv_udp_packet().await.expect("receive packet");
        assert_eq!(src, client_addr);
        match msg {
            celld_logic::sip::SipMessage::Request(req) => {
                assert_eq!(req.method, "INVITE");
                assert_eq!(req.call_id, "call-trans-udp-1");
            }
            _ => panic!("expected SIP Request"),
        }

        // 4. Test egress: send response back to client_addr
        let raw_resp = concat!(
            "SIP/2.0 180 Ringing\r\n",
            "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKudp_trans_1\r\n",
            "From: <sip:alice@sip.example.com>;tag=from1\r\n",
            "To: <sip:bob@sip.example.com>;tag=to1\r\n",
            "Call-ID: call-trans-udp-1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n\r\n"
        );
        send_egress(&client_addr.to_string(), "udp", raw_resp.as_bytes())
            .await
            .expect("send egress should succeed");

        let mut recv_buf = vec![0u8; 1024];
        let (len, from_addr) = client_sock.recv_from(&mut recv_buf).await.unwrap();
        assert_eq!(from_addr, server_addr);
        assert!(core::str::from_utf8(&recv_buf[..len]).unwrap().contains("180 Ringing"));
    }

    #[tokio::test]
    async fn test_sip_do_stub_call_and_dialog_bridging() {
        use crate::engine_api::{RuntimeSipRequest, WorkerConfigOptions};
        use crate::js::{CellJob, Worker};
        use crate::WorkerJob;

        let script = r#"
            import { DurableObject } from "cloudflare:workers";

            export class CallSession extends DurableObject {
                constructor(state, env) {
                    super(state, env);
                    this.state = state;
                }
                async sip(req) {
                    if (!this.ctx.sip) {
                        throw new Error("Missing this.ctx.sip on DurableObject");
                    }
                    const legs = this.ctx.sip.forkInvite(req, ["sip:bob@192.0.2.20:5060"]);
                    if (legs.length !== 1) {
                        throw new Error("Expected 1 leg from forkInvite");
                    }
                    const winnerLeg = legs[0];
                    const resp = winnerLeg.bridgeTo(req, {
                        remoteTag: "bob-tag-123",
                        headers: [["X-Call-Session", "bridged"]],
                    });
                    return resp;
                }
            }

            export default {
                async sip(req, env, ctx) {
                    const id = env.CALL_SESSION.idFromName(req.callId);
                    const stub = env.CALL_SESSION.get(id);
                    return await stub.sip(req);
                }
            };
        "#;

        let options = WorkerConfigOptions {
            src: script.to_string(),
            do_classes: vec!["CallSession".to_string()],
            bindings: vec![("CALL_SESSION".to_string(), "CallSession".to_string())],
            ..Default::default()
        };
        let mut edge_worker = Worker::load(options.clone()).expect("Edge worker should load");
        let mut cell_worker = Worker::load(options).expect("Cell worker should load");

        let (do_call_tx, mut do_call_rx) = tokio::sync::mpsc::unbounded_channel();
        crate::js::set_do_call_tx(do_call_tx);

        let sip_req = RuntimeSipRequest {
            id: 4001,
            method: "INVITE".to_string(),
            uri: "sip:call-center@sip.example.com".to_string(),
            version: "SIP/2.0".to_string(),
            headers: vec![("Call-ID".to_string(), "call-session-test-1".to_string())],
            body: b"v=0\r\no=alice 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 0\r\n".to_vec(),
            transport_protocol: "udp".to_string(),
            source_address: "192.0.2.10:5060".to_string(),
            destination_address: Some("192.0.2.1:5060".to_string()),
            node_id: "node-1".to_string(),
            listener_id: Some("udp-5060".to_string()),
            call_id: "call-session-test-1".to_string(),
            cseq_num: 1,
            cseq_method: "INVITE".to_string(),
            from: "<sip:alice@sip.example.com>;tag=alice-tag".to_string(),
            to: "<sip:call-center@sip.example.com>".to_string(),
            contacts: vec!["<sip:alice@192.0.2.10:5060>".to_string()],
            max_forwards: 70,
            expires: None,
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let job = WorkerJob::Sip {
            queued_at: std::time::Instant::now(),
            entrypoint: None,
            request: Box::new(sip_req),
            provisional_sender: None,
            reply: reply_tx,
        };

        let (begun, mut ops) = edge_worker.turn_begin(job, None);
        let mut edge_entry = begun.expect("edge worker should begin in-flight");
        assert_eq!(ops.len(), 1, "edge worker should have 1 pending op");
        let (op_id, op_future) = ops.remove(0);

        let drive_handle = tokio::spawn(op_future);

        let call = do_call_rx.recv().await.expect("receive DoCallReq from stub.sip()");
        assert_eq!(call.method, "SIP");
        assert_eq!(call.url, "http://cell.internal/sip");
        let sip_req_hdr = call.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("x-celld-sip-req"));
        assert!(sip_req_hdr.is_some(), "x-celld-sip-req header must be present");

        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("cell.sqlite");
        let storage = crate::js::CellStorage {
            path: db_path.to_str().unwrap(),
            epoch: 1,
            replicated_wake: false,
            vfs: None,
        };
        cell_worker.own_cell(&call.scope, Some(storage)).expect("own cell storage");

        let (cell_reply_tx, cell_reply_rx) = tokio::sync::oneshot::channel();
        let cell_job = CellJob::Fetch {
            request_id: None,
            scope: call.scope.clone(),
            name: call.name.clone(),
            url: call.url.clone(),
            method: call.method.clone(),
            body: call.body,
            headers: call.headers,
            reply: cell_reply_tx,
            order: None,
        };

        let (cell_begun, _) = cell_worker.turn_begin_cell(cell_job, None);
        if let Some(mut cell_entry) = cell_begun {
            while !cell_entry.finished() {
                let _ = cell_worker.turn_poll(&mut cell_entry);
            }
        }
        let cell_resp = cell_reply_rx.await.expect("cell should reply").expect("cell execution should succeed");

        assert!(call.reply.send(Ok(cell_resp)).is_ok(), "send reply to edge worker");

        let op_result = drive_handle.await.expect("op future should complete");
        let _ = edge_worker.turn_deliver(&mut edge_entry, op_id, op_result);

        let final_resp = reply_rx.await.expect("worker reply channel").expect("worker should return SipResponse");
        assert_eq!(final_resp.status, 200);
        assert_eq!(final_resp.reason, "OK");
        assert!(final_resp.headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("X-Call-Session") && v == "bridged"));
    }
}


