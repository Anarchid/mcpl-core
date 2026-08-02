use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::grant::advertised_capabilities;
use crate::manifest::DigestError;
use crate::methods::FeatureSetDeclaration;

/// MCPL capability declaration, nested under `experimental.mcpl` in MCP's
/// initialize request/response (SPEC §5.1).
///
/// This object **is** the server's manifest (§17.1). Advertisement mirrors the
/// capability paths of §6.2: a capability with sub-capabilities is an object whose
/// members are the leaves, and a boolean `true` at any level is shorthand for every
/// leaf beneath it.
///
/// Advertisement is an **input** to the host's grant computation, never an
/// authorization (§5.4). Use [`McplCapabilities::advertised_capabilities`] to expand
/// it into paths.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McplCapabilities {
    pub version: String,
    /// Canonical content digest (§17.2). Omitted by servers that do not support §17;
    /// their manifest is fixed for the life of the connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(rename = "pushEvents", default, skip_serializing_if = "Option::is_none")]
    pub push_events: Option<bool>,
    #[serde(rename = "contextHooks", default, skip_serializing_if = "Option::is_none")]
    pub context_hooks: Option<ContextHooksCap>,
    /// Gates `inference/lifecycle` (§10.5). Replaces `context/afterInference`,
    /// removed in 0.5.0.
    #[serde(
        rename = "inferenceLifecycle",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub inference_lifecycle: Option<bool>,
    #[serde(rename = "inferenceRequest", default, skip_serializing_if = "Option::is_none")]
    pub inference_request: Option<InferenceRequestCap>,
    #[serde(rename = "modelInfo", default, skip_serializing_if = "Option::is_none")]
    pub model_info: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<ChannelsCap>,
    // A top-level `rollback` member existed here in 0.4. SPEC 0.5.0 has no such
    // manifest member — §8.1 declares rollback per feature set, and §6.2's closed
    // vocabulary contains no `rollback` path — so it is no longer modelled. A
    // server that still sends one keeps it, byte-for-byte, in `extra` below, so the
    // digest is unaffected; it simply grants nothing.
    #[serde(rename = "featureSets", default, skip_serializing_if = "Option::is_none")]
    pub feature_sets: Option<FeatureSetsAdvertisement>,
    /// Any further manifest member this library does not model.
    ///
    /// Preserved so a fetched manifest round-trips byte-for-byte through the typed
    /// form — the digest (§17.2) covers every member, so silently dropping unknown
    /// ones would compute the wrong revision.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// `featureSets` is dual-shaped: servers declare a map of feature sets (§6.1),
/// while a host advertises only that it supports them at all (§5.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FeatureSetsAdvertisement {
    /// Host form: `"featureSets": true`.
    Supported(bool),
    /// Server form: a map from feature-set name to declaration.
    Declared(BTreeMap<String, FeatureSetDeclaration>),
}

impl FeatureSetsAdvertisement {
    pub fn declarations(&self) -> Option<&BTreeMap<String, FeatureSetDeclaration>> {
        match self {
            FeatureSetsAdvertisement::Declared(map) => Some(map),
            FeatureSetsAdvertisement::Supported(_) => None,
        }
    }
}

/// `inferenceRequest` is either `true` or an object naming its sub-capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InferenceRequestCap {
    Simple(bool),
    Detailed(InferenceRequestDetail),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InferenceRequestDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
}

/// `channels` is either `true` (every leaf) or an object naming the leaves of
/// §14.1. The flat boolean form of 0.4 made `channels.streaming` undeclarable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ChannelsCap {
    Simple(bool),
    Detailed(ChannelsDetail),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelsDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledge: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typing: Option<bool>,
}

/// `contextHooks`. `afterInference` is removed in 0.5.0 (§10.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextHooksCap {
    #[serde(
        rename = "beforeInference",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub before_inference: Option<BeforeInferenceCap>,
}

/// `contextHooks.beforeInference` is either `true` (observe plus all three
/// injection positions) or an object splitting observation from injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BeforeInferenceCap {
    Simple(bool),
    Detailed(BeforeInferenceDetail),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BeforeInferenceDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<InjectCap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InjectCap {
    Simple(bool),
    Detailed(InjectDetail),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InjectDetail {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<bool>,
    #[serde(rename = "beforeUser", default, skip_serializing_if = "Option::is_none")]
    pub before_user: Option<bool>,
    #[serde(rename = "afterUser", default, skip_serializing_if = "Option::is_none")]
    pub after_user: Option<bool>,
}

/// Top-level experimental capabilities wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExperimentalCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcpl: Option<McplCapabilities>,
}

/// Initialize params for MCPL capability negotiation.
/// The MCPL extensions ride on MCP's `initialize` handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McplInitializeParams {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: InitializeCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: ImplementationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McplInitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: InitializeCapabilities,
    #[serde(rename = "serverInfo")]
    pub server_info: ImplementationInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InitializeCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<ExperimentalCapabilities>,
    /// Pass-through for standard MCP capabilities.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementationInfo {
    pub name: String,
    pub version: String,
}

impl McplCapabilities {
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            ..Default::default()
        }
    }

    /// This manifest as raw JSON — the shape the digest is computed over.
    pub fn to_manifest(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("McplCapabilities is always serializable")
    }

    /// Compute this manifest's canonical revision (§17.2).
    ///
    /// This does **not** mutate `self.revision`; the caller decides whether to
    /// publish it. The revision must be content-derived, never hand-maintained or
    /// tied to a package version (§17.1).
    pub fn compute_revision(&self) -> Result<String, DigestError> {
        crate::manifest::manifest_revision(&self.to_manifest())
    }

    /// Expand this advertisement into capability paths via the generic recursive
    /// walk of §5.1/§5.4.
    ///
    /// The result is what the server *claims*, not what it may do. `tools` never
    /// appears — it is an MCP capability, not an MCPL member.
    pub fn advertised_capabilities(&self) -> BTreeSet<String> {
        advertised_capabilities(&self.to_manifest())
    }

    /// Whether the advertisement claims `path`.
    ///
    /// This is not an authorization check. Use
    /// [`crate::grant::CapabilityGrant::allows`] for that.
    pub fn advertises(&self, path: &str) -> bool {
        self.advertised_capabilities().contains(path)
    }

    /// Declared feature sets, if this is a server advertisement.
    pub fn declarations(&self) -> Option<&BTreeMap<String, FeatureSetDeclaration>> {
        self.feature_sets.as_ref().and_then(|f| f.declarations())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_advertisement_expands_recursively() {
        let caps: McplCapabilities = serde_json::from_str(
            r#"{
                "version": "0.5",
                "pushEvents": true,
                "contextHooks": { "beforeInference": {
                    "observe": true,
                    "inject": { "system": false, "beforeUser": true, "afterUser": true }
                } },
                "inferenceLifecycle": true,
                "inferenceRequest": { "streaming": true },
                "modelInfo": true,
                "channels": { "register": true, "publish": true, "incoming": true }
            }"#,
        )
        .unwrap();

        let adv = caps.advertised_capabilities();
        assert!(adv.contains("pushEvents"));
        assert!(adv.contains("inferenceLifecycle"));
        assert!(adv.contains("inferenceRequest"));
        assert!(adv.contains("inferenceRequest.streaming"));
        assert!(adv.contains("modelInfo"));
        assert!(adv.contains("contextHooks.beforeInference.observe"));
        assert!(adv.contains("contextHooks.beforeInference.inject.beforeUser"));
        assert!(!adv.contains("contextHooks.beforeInference.inject.system"));
        assert!(adv.contains("channels.register"));
        assert!(!adv.contains("channels.streaming"));
        assert!(!adv.contains("tools"));
    }

    #[test]
    fn channels_streaming_is_declarable() {
        let caps: McplCapabilities =
            serde_json::from_str(r#"{"version":"0.5","channels":{"streaming":true}}"#).unwrap();
        assert!(caps.advertises("channels.streaming"));
    }

    #[test]
    fn unknown_manifest_members_round_trip() {
        let raw = r#"{"version":"0.5","pushEvents":true,"vendorThing":{"a":[1,2]}}"#;
        let caps: McplCapabilities = serde_json::from_str(raw).unwrap();
        assert!(caps.extra.contains_key("vendorThing"));
        let back = serde_json::to_value(&caps).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(raw).unwrap());
    }

    #[test]
    fn revision_is_excluded_from_its_own_digest() {
        let mut caps = McplCapabilities::new("0.5");
        caps.push_events = Some(true);
        let rev = caps.compute_revision().unwrap();
        caps.revision = Some(rev.clone());
        assert_eq!(caps.compute_revision().unwrap(), rev);
    }
}
