use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::types::ContentBlock;

// ── Feature Sets (Section 6) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSetDeclaration {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub uses: Vec<String>,
    #[serde(default)]
    pub rollback: bool,
    #[serde(rename = "hostState", default)]
    pub host_state: bool,
}

/// featureSets/update (Host → Server, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSetsUpdateParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<HashMap<String, ScopeConfig>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub whitelist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blacklist: Option<Vec<String>>,
}

/// featureSets/changed (Server → Host, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureSetsChangedParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added: Option<HashMap<String, FeatureSetDeclaration>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
}

// ── Scoped Access (Section 7) ──

/// scope/elevate (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeElevateParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub scope: ScopeElevateScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeElevateScope {
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeElevateResult {
    pub approved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ── State Management (Section 8) ──

/// state/rollback (Host → Server, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRollbackParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub checkpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRollbackResult {
    pub checkpoint: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// State checkpoint metadata (Section 8.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCheckpoint {
    pub id: String,
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// JSON Patch operation (RFC 6902) for host-managed state (Section 8.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonPatchOperation {
    pub op: JsonPatchOp,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JsonPatchOp {
    Add,
    Remove,
    Replace,
    Move,
    Copy,
    Test,
}

/// State included in tool results when hostState is enabled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostManagedState {
    pub checkpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<Vec<JsonPatchOperation>>,
}

// ── Push Events (Section 9) ──

/// push/event (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushEventParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    #[serde(rename = "eventId")]
    pub event_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<serde_json::Value>,
    pub payload: PushEventPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushEventPayload {
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushEventResult {
    pub accepted: bool,
    #[serde(rename = "inferenceId", skip_serializing_if = "Option::is_none")]
    pub inference_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ── Context Hooks (Section 10) ──

/// Model info included in context hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub vendor: String,
    #[serde(rename = "contextWindow")]
    pub context_window: u32,
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// context/beforeInference (Host → Server, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBeforeInferenceParams {
    #[serde(rename = "inferenceId")]
    pub inference_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "turnIndex")]
    pub turn_index: u32,
    #[serde(rename = "userMessage")]
    pub user_message: Option<String>,
    pub model: ModelInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextInjection {
    pub namespace: String,
    pub position: ContextInjectionPosition,
    pub content: ContextInjectionContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ContextInjectionPosition {
    System,
    BeforeUser,
    AfterUser,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextInjectionContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBeforeInferenceResult {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    #[serde(rename = "contextInjections")]
    pub context_injections: Vec<ContextInjection>,
}

/// context/afterInference (Host → Server, Request or Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAfterInferenceParams {
    #[serde(rename = "inferenceId")]
    pub inference_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "turnIndex")]
    pub turn_index: u32,
    #[serde(rename = "userMessage")]
    pub user_message: String,
    #[serde(rename = "assistantMessage")]
    pub assistant_message: String,
    pub model: ModelInfo,
    pub usage: InferenceUsage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channels: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextAfterInferenceResult {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    #[serde(rename = "modifiedResponse", skip_serializing_if = "Option::is_none")]
    pub modified_response: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

// ── Server-Initiated Inference (Section 11) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceUsage {
    #[serde(rename = "inputTokens")]
    pub input_tokens: u32,
    #[serde(rename = "outputTokens")]
    pub output_tokens: u32,
}

/// inference/request (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequestParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    #[serde(rename = "conversationId", skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    pub messages: Vec<InferenceMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferences: Option<InferencePreferences>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferencePreferences {
    #[serde(rename = "maxTokens", skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequestResult {
    pub content: String,
    pub model: String,
    #[serde(rename = "finishReason")]
    pub finish_reason: String,
    pub usage: InferenceUsage,
}

/// inference/chunk (Host → Server, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceChunkParams {
    #[serde(rename = "requestId")]
    pub request_id: i64,
    pub index: u32,
    pub delta: String,
}

// ── Model Information (Section 12) ──

/// model/info result (same as ModelInfo)
pub type ModelInfoResult = ModelInfo;

// ── Channels (Section 14) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDescriptor {
    pub id: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub label: String,
    pub direction: ChannelDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelDirection {
    Outbound,
    Inbound,
    Bidirectional,
}

/// channels/register (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsRegisterParams {
    pub channels: Vec<ChannelDescriptor>,
}

/// channels/changed (Server → Host, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsChangedParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<ChannelDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<Vec<ChannelDescriptor>>,
}

/// channels/list (Either direction, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsListResult {
    pub channels: Vec<ChannelDescriptor>,
}

/// channels/open (Host → Server, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsOpenParams {
    #[serde(rename = "type")]
    pub channel_type: String,
    pub address: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsOpenResult {
    pub channel: ChannelDescriptor,
}

/// channels/close (Host → Server, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsCloseParams {
    #[serde(rename = "channelId")]
    pub channel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsCloseResult {
    pub closed: bool,
}

/// channels/outgoing/chunk (Host → Server, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsOutgoingChunkParams {
    #[serde(rename = "inferenceId")]
    pub inference_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    pub index: u32,
    pub delta: String,
}

/// channels/outgoing/complete (Host → Server, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsOutgoingCompleteParams {
    #[serde(rename = "inferenceId")]
    pub inference_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    pub content: Vec<ContentBlock>,
}

/// channels/publish (Host → Server, Notification or Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsPublishParams {
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "channelId")]
    pub channel_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsPublishResult {
    pub delivered: bool,
    #[serde(rename = "messageId", skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

/// channels/incoming (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsIncomingParams {
    pub messages: Vec<IncomingChannelMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingChannelMessage {
    #[serde(rename = "channelId")]
    pub channel_id: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "threadId", skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    pub author: MessageAuthor,
    pub timestamp: String,
    pub content: Vec<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageAuthor {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsIncomingResult {
    pub results: Vec<IncomingMessageResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessageResult {
    #[serde(rename = "messageId")]
    pub message_id: String,
    pub accepted: bool,
    #[serde(rename = "conversationId", skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
}

// ── Method name constants ──

pub mod method {
    pub const INITIALIZE: &str = "initialize";
    pub const FEATURE_SETS_UPDATE: &str = "featureSets/update";
    pub const FEATURE_SETS_CHANGED: &str = "featureSets/changed";
    pub const SCOPE_ELEVATE: &str = "scope/elevate";
    pub const STATE_ROLLBACK: &str = "state/rollback";
    pub const PUSH_EVENT: &str = "push/event";
    pub const CONTEXT_BEFORE_INFERENCE: &str = "context/beforeInference";
    pub const CONTEXT_AFTER_INFERENCE: &str = "context/afterInference";
    pub const INFERENCE_REQUEST: &str = "inference/request";
    pub const INFERENCE_CHUNK: &str = "inference/chunk";
    pub const MODEL_INFO: &str = "model/info";
    pub const CHANNELS_REGISTER: &str = "channels/register";
    pub const CHANNELS_CHANGED: &str = "channels/changed";
    pub const CHANNELS_LIST: &str = "channels/list";
    pub const CHANNELS_OPEN: &str = "channels/open";
    pub const CHANNELS_CLOSE: &str = "channels/close";
    pub const CHANNELS_OUTGOING_CHUNK: &str = "channels/outgoing/chunk";
    pub const CHANNELS_OUTGOING_COMPLETE: &str = "channels/outgoing/complete";
    pub const CHANNELS_PUBLISH: &str = "channels/publish";
    pub const CHANNELS_INCOMING: &str = "channels/incoming";
}
