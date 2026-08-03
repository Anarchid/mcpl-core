use serde::{Deserialize, Serialize};

use crate::tags::TagOntology;
use crate::types::ContentBlock;

// ── Feature Sets (Section 6) ──

/// A declared feature set (SPEC §6.1, App. B.2).
///
/// Feature sets are keyed by name in the `featureSets` map, so the name is not a
/// member of the declaration itself.
///
/// `description` and `uses` are both required by App. B.2. They are nonetheless
/// deserialized with defaults rather than as hard parse failures: §6.2 makes an
/// absent `uses` an `invalid_uses` *diagnosis* (§6.6), and §17.5 says a manifest
/// that does not parse at all leaves the previous manifest standing — so failing the
/// whole parse would be strictly worse than disabling the one bad declaration.
/// Absent `uses` therefore collapses to empty, which
/// [`crate::grant::validate_uses`] rejects with the same reason §6.2 assigns to it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureSetDeclaration {
    #[serde(default)]
    pub description: String,
    /// Capability paths from the closed §6.2 vocabulary. Absent, empty, or
    /// containing an unrecognised value ⇒ `invalid_uses`.
    #[serde(default)]
    pub uses: Vec<String>,
    /// §8.1: this feature set supports rollback.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rollback: bool,
    /// Open-world catalog of the tags this feature set emits (§16.4).
    #[serde(rename = "tagOntology", default, skip_serializing_if = "Option::is_none")]
    pub tag_ontology: Option<TagOntology>,
}

/// `featureSets/update` (Host → Server, Notification **or** Request) — SPEC §6.7.
///
/// Hosts MUST send it as a **Request** for any change to the effective grant,
/// including the initial policy (§5.3) and including when nothing is enabled or
/// disabled. A Notification is valid only for purely descriptive feature metadata
/// that does not alter the grant, and cannot establish a ready state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeatureSetsUpdateParams {
    /// **The sole normative allowlist** (§5.4). Every path not present is denied;
    /// absence is the denial.
    ///
    /// Absent here means "this message does not alter the grant" — the descriptive
    /// Notification form of §6.7. It never means "grant everything".
    #[serde(
        rename = "effectiveCapabilities",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_capabilities: Option<Vec<String>>,
    /// Derived **diagnostic data only** (§5.4). MAY be omitted, and MUST NOT
    /// participate in any authorization decision.
    #[serde(
        rename = "deniedCapabilities",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub denied_capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled: Option<Vec<String>>,
}

/// The response to `featureSets/update` is a **degradation receipt**, not an
/// acknowledgement (SPEC §6.7).
///
/// The two outcomes carry different obligations, so they are different types.
/// §6.7: "`fallback` is REQUIRED when `accepted` is `false`" — a refusal names its
/// own consequence rather than leaving the host to guess between mcp-only and
/// closing the transport — while an acceptance carries no `fallback` at all. The
/// split makes the requiredness structural instead of a runtime check.
///
/// Consequence testimony is not policy authority: the receipt reports what the
/// server *will do*, never what it is *entitled to*. A host MUST NOT widen any grant
/// in response to a receipt, and a refusal MUST NOT reach the policy engine as an
/// input.
///
/// On the wire both forms are one object distinguished by the `accepted` boolean,
/// which is what the manual `Serialize`/`Deserialize` implementations below encode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureSetsUpdateResult {
    /// `accepted: true`.
    Accepted(AcceptedUpdate),
    /// `accepted: false`.
    Refused(RefusedUpdate),
}

/// The `accepted: true` receipt (§6.7).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AcceptedUpdate {
    /// e.g. `"degraded"`. The specification shows this value but defines no closed
    /// enum, so it is left as a free string. §6.7: when nothing degraded, **omit**
    /// it rather than inventing a value.
    pub mode: Option<String>,
    pub unavailable_features: Option<Vec<UnavailableFeature>>,
    pub notes: Option<Vec<String>>,
}

/// The `accepted: false` refusal receipt (§6.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedUpdate {
    /// Which weaker outcome applies. **Required** (§6.7): naming the consequence is
    /// the server's job, and its absence would be a silent value at exactly the
    /// point the host chooses between mcp-only and closing the transport.
    /// `accepted: false` does **not** mean close the transport; the host MAY close
    /// regardless.
    pub fallback: UpdateFallback,
    pub missing_capabilities: Option<Vec<String>>,
    pub reason: Option<String>,
}

/// The wire shape shared by both receipt forms.
#[derive(Serialize, Deserialize)]
struct FeatureSetsUpdateResultWire {
    accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    #[serde(
        rename = "unavailableFeatures",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    unavailable_features: Option<Vec<UnavailableFeature>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fallback: Option<UpdateFallback>,
    #[serde(
        rename = "missingCapabilities",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    missing_capabilities: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl Serialize for FeatureSetsUpdateResult {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let wire = match self {
            FeatureSetsUpdateResult::Accepted(a) => FeatureSetsUpdateResultWire {
                accepted: true,
                mode: a.mode.clone(),
                unavailable_features: a.unavailable_features.clone(),
                notes: a.notes.clone(),
                fallback: None,
                missing_capabilities: None,
                reason: None,
            },
            FeatureSetsUpdateResult::Refused(r) => FeatureSetsUpdateResultWire {
                accepted: false,
                mode: None,
                unavailable_features: None,
                notes: None,
                fallback: Some(r.fallback),
                missing_capabilities: r.missing_capabilities.clone(),
                reason: r.reason.clone(),
            },
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FeatureSetsUpdateResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = FeatureSetsUpdateResultWire::deserialize(deserializer)?;
        if wire.accepted {
            Ok(FeatureSetsUpdateResult::Accepted(AcceptedUpdate {
                mode: wire.mode,
                unavailable_features: wire.unavailable_features,
                notes: wire.notes,
            }))
        } else {
            // §6.7: `fallback` is REQUIRED when `accepted` is `false`.
            let fallback = wire.fallback.ok_or_else(|| {
                serde::de::Error::custom(
                    "refusal receipt (`accepted: false`) is missing required `fallback` (§6.7)",
                )
            })?;
            Ok(FeatureSetsUpdateResult::Refused(RefusedUpdate {
                fallback,
                missing_capabilities: wire.missing_capabilities,
                reason: wire.reason,
            }))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateFallback {
    /// Disable MCPL, retain tools, resources and prompts (§3.2).
    McpOnly,
    Close,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnavailableFeature {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    #[serde(rename = "missingCapabilities", default)]
    pub missing_capabilities: Vec<String>,
    /// e.g. `"disabled"`. No closed enum is specified, but §6.7 makes it
    /// **required**: "Each `unavailableFeatures` entry MUST carry `effect`."
    pub effect: String,
}

// ── Section 7 (Scoped Access) is removed in 0.5.0 ──
//
// `scope/elevate` and scope whitelist/blacklist configuration are gone: the host
// matched a *server-supplied* `scope.label` against its own whitelist. MCPL now has
// two authorization layers, not three.

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
    /// Full state at the rolled-back checkpoint (for host-managed state).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// state/update (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdateParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub checkpoint: String,
    pub parent: Option<String>,
    /// Full state (mutually exclusive with patch). Both absent = opaque checkpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    /// JSON Patch delta from parent (mutually exclusive with data).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<Vec<JsonPatchOperation>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateUpdateResult {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// state/get (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateGetParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateGetResult {
    pub checkpoint: Option<String>,
    pub data: serde_json::Value,
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
    /// Namespaced semantic labels (§9.2, §16). OPTIONAL.
    ///
    /// Tags are **untrusted descriptive claims** authored by the producer, exactly
    /// like `origin` and `metadata`. Admission is decided by the capability grant
    /// and channel authorization *before* any tag is read (§16.6); a tag never
    /// widens a grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
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
    /// §14.4: channel context the host MAY include so servers can adapt. The host
    /// controls whether to include it.
    ///
    /// This belongs to `context/beforeInference`. It was previously attached to
    /// `context/afterInference`, which §14.4 never mentioned and which no longer
    /// exists (§10.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<BeforeInferenceChannelContext>,
}

/// §14.4 `channels` context on `context/beforeInference`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BeforeInferenceChannelContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incoming: Option<IncomingChannelRef>,
    #[serde(
        rename = "defaultOutgoing",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_outgoing: Option<OutgoingChannelRef>,
    /// Channel ids the host considers available for this turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingChannelRef {
    #[serde(rename = "channelId")]
    pub channel_id: String,
    #[serde(rename = "messageId", default, skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(rename = "threadId", default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutgoingChannelRef {
    #[serde(rename = "channelId")]
    pub channel_id: String,
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

// ── inference/lifecycle (Section 10.5) ──
//
// `context/afterInference` is **removed in 0.5.0**, along with `modifiedResponse`
// and its blocking form. It handed every subscribing server the user message plus
// the joined assistant message, including prose destined for other servers'
// surfaces. Servers needing turn *content* take it per-channel and moderated via
// `channels/outgoing/complete`.

/// `inference/lifecycle` (Host → Server, **Notification**) — SPEC §10.5.
/// Gated on the `inferenceLifecycle` capability.
///
/// Metadata only. It **MUST NOT** carry message content — no `userMessage`, no
/// `assistantMessage`, no injected context, no tool arguments or results. Those
/// fields do not exist on this type, deliberately.
///
/// **Delivery is best-effort.** It is unacknowledged, so:
///
/// - A host attempts exactly one terminal phase per emitted `started`, on every
///   exit path it controls. A host that loses control (crash, kill, transport loss)
///   may never send one. There is no outbox, replay, acknowledgement or event
///   identity, and this library adds none.
/// - Consumers **MUST** deduplicate terminals by `inferenceId`, tolerate a missing
///   terminal, and **retain a safety timeout** on any state machine gated on turn
///   completion.
///
/// §14.5: a server **MUST NOT** deliver content to its surface in response to a
/// lifecycle notification. Delivery happens only via `channels/publish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceLifecycleParams {
    #[serde(rename = "inferenceId")]
    pub inference_id: String,
    #[serde(rename = "conversationId")]
    pub conversation_id: String,
    #[serde(rename = "turnIndex")]
    pub turn_index: u32,
    pub phase: InferencePhase,
    /// OPTIONAL; only if `modelInfo` is granted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelInfo>,
    /// OPTIONAL; `completed` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<InferenceUsage>,
}

/// Lifecycle position (§10.5). `completed`, `aborted` and `failed` are terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InferencePhase {
    Started,
    Completed,
    Aborted,
    Failed,
}

impl InferencePhase {
    /// Whether this phase ends the inference. Consumers dedupe terminals by
    /// `inferenceId`; a second terminal for an already-terminated id is a
    /// conformance defect and should be logged, not acted on.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, InferencePhase::Started)
    }
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
///
/// §14.5: this carries an **array** of descriptors, and the host MUST authorize
/// **each descriptor independently**. Whole-request authorization would let one
/// permitted descriptor carry nine forbidden ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsRegisterParams {
    pub channels: Vec<ChannelDescriptor>,
}

/// channels/changed (Server → Host, Notification **or** Request) — §14.5.
///
/// Dual-mode. As a Notification it cannot carry a result, so partial rejection is
/// inexpressible: a host whose policy can reject descriptors MUST require the
/// Request form, and a server MUST use it when signalled. A host that receives a
/// Notification it must partially reject filters itemwise **and** emits a
/// diagnostic — never silently, since silent filtering leaves the two sides
/// disagreeing about which channels exist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsChangedParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added: Option<Vec<ChannelDescriptor>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub removed: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<Vec<ChannelDescriptor>>,
}

/// Itemized result of `channels/register` or the Request form of
/// `channels/changed` (§14.5): one entry per submitted descriptor.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelsRegisterResult {
    pub results: Vec<ChannelRegistrationResult>,
}

/// `channels/changed` (Request form) returns the same shape as
/// `channels/register` (§14.5).
pub type ChannelsChangedResult = ChannelsRegisterResult;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRegistrationResult {
    pub id: String,
    pub accepted: bool,
    /// e.g. `"capability_denied"`. §14.5 shows this value; no closed enum is
    /// specified, so it is left as a free string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
///
/// §14.5: every message MUST be validated at receipt against the **current** grant
/// and the **actually registered** channel — not against the channel id the message
/// claims, and not against the grant as it stood at registration.
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
    /// Namespaced semantic labels (§14.3, §16). OPTIONAL.
    ///
    /// Untrusted producer claims. Whether this message is admitted at all is
    /// already settled by the grant and channel authorization before any tag is
    /// read (§16.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
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

// ── Branches (Section 15) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchInfo {
    pub name: String,
    pub head: u64,
    #[serde(rename = "isCurrent")]
    pub is_current: bool,
    pub parent: Option<String>,
    #[serde(rename = "branchPoint")]
    pub branch_point: Option<u64>,
}

/// branches/list (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesListParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesListResult {
    pub branches: Vec<BranchInfo>,
}

/// branches/current (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesCurrentParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesCurrentResult {
    pub name: String,
    pub head: u64,
}

/// branches/create (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesCreateParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(rename = "atCheckpoint", skip_serializing_if = "Option::is_none")]
    pub at_checkpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesCreateResult {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// branches/switch (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesSwitchParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesSwitchResult {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// branches/delete (Server → Host, Request)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesDeleteParams {
    #[serde(rename = "featureSet")]
    pub feature_set: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesDeleteResult {
    pub accepted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// branches/changed (Host → Server, Notification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchesChangedParams {
    pub event: BranchesChangedEvent,
    pub branch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BranchesChangedEvent {
    Created,
    Switched,
    Deleted,
}

// ── Method name constants ──

pub mod method {
    pub const INITIALIZE: &str = "initialize";
    pub const FEATURE_SETS_UPDATE: &str = "featureSets/update";
    // `featureSets/changed` is removed in 0.5.0 (§6.7): it carried a
    // server-authored account of what changed. `scope/elevate` is removed with
    // §7. Neither has a constant, so a caller cannot dispatch on one by accident.
    pub const MCPL_MANIFEST: &str = "mcpl/manifest";
    pub const MCPL_MANIFEST_CHANGED: &str = "mcpl/manifestChanged";
    pub const STATE_UPDATE: &str = "state/update";
    pub const STATE_GET: &str = "state/get";
    pub const STATE_ROLLBACK: &str = "state/rollback";
    pub const PUSH_EVENT: &str = "push/event";
    pub const CONTEXT_BEFORE_INFERENCE: &str = "context/beforeInference";
    /// §10.5. Replaces `context/afterInference`, removed in 0.5.0.
    pub const INFERENCE_LIFECYCLE: &str = "inference/lifecycle";
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
    /// Named by §14.1's authorization table. §14.3 defines no parameter shape for
    /// it, so this library ships the name and the capability mapping only — it does
    /// not invent params.
    pub const CHANNELS_ACKNOWLEDGE: &str = "channels/acknowledge";
    /// Same as [`CHANNELS_ACKNOWLEDGE`]: named by §14.1, shape undefined in §14.3.
    pub const CHANNELS_TYPING: &str = "channels/typing";
    pub const BRANCHES_LIST: &str = "branches/list";
    pub const BRANCHES_CURRENT: &str = "branches/current";
    pub const BRANCHES_CREATE: &str = "branches/create";
    pub const BRANCHES_SWITCH: &str = "branches/switch";
    pub const BRANCHES_DELETE: &str = "branches/delete";
    pub const BRANCHES_CHANGED: &str = "branches/changed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_carries_metadata_only() {
        // §10.5: the content fields do not exist. Sending them is not a matter of
        // policy — they cannot be represented, and unknown members are dropped.
        let raw = serde_json::json!({
            "inferenceId": "inf_xyz",
            "conversationId": "conv_123",
            "turnIndex": 7,
            "phase": "completed",
            "usage": { "inputTokens": 1250, "outputTokens": 340 },
            "userMessage": "leaked?",
            "assistantMessage": "leaked?"
        });
        let params: InferenceLifecycleParams = serde_json::from_value(raw).unwrap();
        assert_eq!(params.phase, InferencePhase::Completed);
        assert!(params.phase.is_terminal());

        let back = serde_json::to_value(&params).unwrap();
        assert!(back.get("userMessage").is_none());
        assert!(back.get("assistantMessage").is_none());
        assert!(back.get("modifiedResponse").is_none());
    }

    #[test]
    fn lifecycle_phases_are_the_four_spec_values() {
        for (raw, phase, terminal) in [
            ("started", InferencePhase::Started, false),
            ("completed", InferencePhase::Completed, true),
            ("aborted", InferencePhase::Aborted, true),
            ("failed", InferencePhase::Failed, true),
        ] {
            let parsed: InferencePhase =
                serde_json::from_value(serde_json::Value::String(raw.into())).unwrap();
            assert_eq!(parsed, phase);
            assert_eq!(parsed.is_terminal(), terminal, "{raw}");
        }
        assert!(serde_json::from_str::<InferencePhase>(r#""cancelled""#).is_err());
    }

    #[test]
    fn channel_context_rides_on_before_inference() {
        // §14.4 attaches this to `context/beforeInference`, not to the removed
        // `context/afterInference`.
        let params: ContextBeforeInferenceParams = serde_json::from_value(serde_json::json!({
            "inferenceId": "inf_1",
            "conversationId": "conv_1",
            "turnIndex": 0,
            "userMessage": "hi",
            "model": { "id": "m", "vendor": "v", "contextWindow": 100 },
            "channels": {
                "incoming": { "channelId": "discord:#general", "messageId": "dmsg_123",
                              "threadId": "t_42" },
                "defaultOutgoing": { "channelId": "discord:#general" },
                "candidates": ["ui", "discord:#general"]
            }
        }))
        .unwrap();
        let channels = params.channels.expect("channel context");
        assert_eq!(channels.incoming.unwrap().channel_id, "discord:#general");
        assert_eq!(channels.default_outgoing.unwrap().channel_id, "discord:#general");
        assert_eq!(channels.candidates.unwrap().len(), 2);
    }

    #[test]
    fn incoming_messages_carry_tags() {
        let params: ChannelsIncomingParams = serde_json::from_value(serde_json::json!({
            "messages": [{
                "channelId": "discord:#general",
                "messageId": "dmsg_123",
                "author": { "id": "u_777", "name": "Alice" },
                "timestamp": "2026-03-05T10:30:00Z",
                "content": [{ "type": "text", "text": "hi" }],
                "tags": ["chat:mention", "chat:from-human"]
            }]
        }))
        .unwrap();
        assert_eq!(
            params.messages[0].tags.as_deref(),
            Some(&["chat:mention".to_string(), "chat:from-human".to_string()][..])
        );
        // Absent tags stay absent rather than becoming an empty set.
        let untagged: IncomingChannelMessage = serde_json::from_value(serde_json::json!({
            "channelId": "c", "messageId": "m",
            "author": { "id": "u", "name": "n" },
            "timestamp": "2026-03-05T10:30:00Z",
            "content": []
        }))
        .unwrap();
        assert!(untagged.tags.is_none());
        assert!(serde_json::to_value(&untagged).unwrap().get("tags").is_none());
    }

    #[test]
    fn registration_results_are_itemized() {
        // §14.5: one entry per submitted descriptor, so a partial rejection is
        // expressible instead of collapsing to a single verdict on the array.
        let result: ChannelsRegisterResult = serde_json::from_value(serde_json::json!({
            "results": [
                { "id": "discord:#general", "accepted": true },
                { "id": "discord:#admin", "accepted": false, "reason": "capability_denied" }
            ]
        }))
        .unwrap();
        assert_eq!(result.results.len(), 2);
        assert!(!result.results[1].accepted);
        assert_eq!(result.results[1].reason.as_deref(), Some("capability_denied"));
    }

    #[test]
    fn feature_set_declaration_matches_appendix_b2() {
        // App. B.2 requires `description` and `uses`; the name is the map key.
        let decl: FeatureSetDeclaration = serde_json::from_value(serde_json::json!({
            "description": "Demo",
            "uses": ["channels.publish", "pushEvents"]
        }))
        .unwrap();
        assert_eq!(decl.description, "Demo");
        assert_eq!(decl.uses.len(), 2);
        assert!(!decl.rollback);

        // An absent `uses` collapses to empty, which §6.2 makes `invalid_uses`
        // rather than a parse failure — §17.5 keeps a partly-invalid manifest usable.
        let bad: FeatureSetDeclaration =
            serde_json::from_value(serde_json::json!({ "description": "Demo" })).unwrap();
        assert!(crate::grant::validate_uses(&bad.uses).is_err());
    }

    #[test]
    fn refusal_receipt_requires_fallback() {
        // §6.7: "`fallback` is REQUIRED when `accepted` is `false`" — the refusal
        // names its own consequence.
        let refused: FeatureSetsUpdateResult = serde_json::from_value(serde_json::json!({
            "accepted": false,
            "fallback": "mcp-only",
            "missingCapabilities": ["inferenceLifecycle"],
            "reason": "cannot operate without lifecycle"
        }))
        .unwrap();
        let FeatureSetsUpdateResult::Refused(r) = &refused else {
            panic!("accepted: false must deserialize as Refused");
        };
        assert_eq!(r.fallback, UpdateFallback::McpOnly);

        // A refusal that names no fallback is malformed, not a silent default.
        assert!(serde_json::from_value::<FeatureSetsUpdateResult>(serde_json::json!({
            "accepted": false,
            "reason": "no consequence named"
        }))
        .is_err());

        // An acceptance carries no fallback at all — structurally.
        let accepted: FeatureSetsUpdateResult =
            serde_json::from_value(serde_json::json!({ "accepted": true })).unwrap();
        assert!(matches!(accepted, FeatureSetsUpdateResult::Accepted(_)));
        let wire = serde_json::to_value(&accepted).unwrap();
        assert_eq!(wire.get("accepted"), Some(&serde_json::Value::Bool(true)));
        assert!(wire.get("fallback").is_none());
        // §6.7: when nothing degraded, `mode` is omitted, not invented.
        assert!(wire.get("mode").is_none());

        // Round trip of the refusal keeps the wire shape.
        let wire = serde_json::to_value(&refused).unwrap();
        assert_eq!(wire.get("accepted"), Some(&serde_json::Value::Bool(false)));
        assert_eq!(wire.get("fallback"), Some(&serde_json::json!("mcp-only")));
    }

    #[test]
    fn unavailable_feature_entries_require_effect() {
        // §6.7: "Each `unavailableFeatures` entry MUST carry `effect`."
        let receipt: FeatureSetsUpdateResult = serde_json::from_value(serde_json::json!({
            "accepted": true,
            "mode": "degraded",
            "unavailableFeatures": [
                { "featureSet": "memory.extraction",
                  "missingCapabilities": ["inferenceLifecycle"],
                  "effect": "disabled" }
            ],
            "notes": []
        }))
        .unwrap();
        let FeatureSetsUpdateResult::Accepted(a) = &receipt else {
            panic!("accepted: true must deserialize as Accepted");
        };
        assert_eq!(
            a.unavailable_features.as_ref().unwrap()[0].effect,
            "disabled"
        );

        assert!(serde_json::from_value::<UnavailableFeature>(serde_json::json!({
            "featureSet": "memory.extraction",
            "missingCapabilities": ["inferenceLifecycle"]
        }))
        .is_err());
    }
}
