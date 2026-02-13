use serde::{Deserialize, Serialize};

use crate::methods::FeatureSetDeclaration;

/// MCPL capability declaration, nested under `experimental.mcpl` in MCP's
/// initialize request/response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McplCapabilities {
    pub version: String,
    #[serde(rename = "pushEvents", default, skip_serializing_if = "Option::is_none")]
    pub push_events: Option<bool>,
    #[serde(rename = "contextHooks", default, skip_serializing_if = "Option::is_none")]
    pub context_hooks: Option<ContextHooksCap>,
    #[serde(rename = "inferenceRequest", default, skip_serializing_if = "Option::is_none")]
    pub inference_request: Option<InferenceRequestCap>,
    #[serde(rename = "streamObserver", default, skip_serializing_if = "Option::is_none")]
    pub stream_observer: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<bool>,
    #[serde(rename = "modelInfo", default, skip_serializing_if = "Option::is_none")]
    pub model_info: Option<bool>,
    #[serde(rename = "featureSets", default, skip_serializing_if = "Option::is_none")]
    pub feature_sets: Option<Vec<FeatureSetDeclaration>>,
    #[serde(rename = "scopedAccess", default, skip_serializing_if = "Option::is_none")]
    pub scoped_access: Option<bool>,
}

/// The `inferenceRequest` capability can be a simple boolean `true` or
/// an object `{ streaming: bool }` for finer-grained control.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InferenceRequestCap {
    Simple(bool),
    Detailed(InferenceRequestDetail),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequestDetail {
    pub streaming: bool,
}

impl InferenceRequestCap {
    pub fn is_enabled(&self) -> bool {
        match self {
            InferenceRequestCap::Simple(b) => *b,
            InferenceRequestCap::Detailed(_) => true,
        }
    }

    pub fn supports_streaming(&self) -> bool {
        match self {
            InferenceRequestCap::Simple(_) => false,
            InferenceRequestCap::Detailed(d) => d.streaming,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextHooksCap {
    #[serde(rename = "beforeInference", default)]
    pub before_inference: bool,
    #[serde(rename = "afterInference", default, skip_serializing_if = "Option::is_none")]
    pub after_inference: Option<AfterInferenceCap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterInferenceCap {
    #[serde(default)]
    pub blocking: bool,
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

    pub fn has_push_events(&self) -> bool {
        self.push_events.unwrap_or(false)
    }

    pub fn has_channels(&self) -> bool {
        self.channels.unwrap_or(false)
    }

    pub fn has_rollback(&self) -> bool {
        self.rollback.unwrap_or(false)
    }

    pub fn has_inference_request(&self) -> bool {
        self.inference_request.as_ref().map_or(false, |c| c.is_enabled())
    }

    pub fn has_inference_streaming(&self) -> bool {
        self.inference_request.as_ref().map_or(false, |c| c.supports_streaming())
    }

    pub fn has_model_info(&self) -> bool {
        self.model_info.unwrap_or(false)
    }

    pub fn has_stream_observer(&self) -> bool {
        self.stream_observer.unwrap_or(false)
    }

    pub fn has_scoped_access(&self) -> bool {
        self.scoped_access.unwrap_or(false)
    }
}
