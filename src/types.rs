use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 message types for MCPL transport.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonRpcMessage {
    Request(JsonRpcRequest),
    Response(JsonRpcResponse),
    Notification(JsonRpcNotification),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum JsonRpcId {
    Number(i64),
    String(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcRequest {
    pub fn new(id: impl Into<JsonRpcId>, method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

impl JsonRpcResponse {
    pub fn success(id: JsonRpcId, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: JsonRpcId, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(error),
        }
    }
}

impl JsonRpcNotification {
    pub fn new(method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
        }
    }
}

impl From<i64> for JsonRpcId {
    fn from(n: i64) -> Self {
        JsonRpcId::Number(n)
    }
}

impl From<String> for JsonRpcId {
    fn from(s: String) -> Self {
        JsonRpcId::String(s)
    }
}

impl From<&str> for JsonRpcId {
    fn from(s: &str) -> Self {
        JsonRpcId::String(s.to_string())
    }
}

// MCPL error codes (Appendix A, §6.6, §14.6)
pub const ERR_FEATURE_SET_NOT_ENABLED: i32 = -32001;
/// §6.6 / §14.6: the method requires a capability not in the effective grant
/// (§5.4). `data` carries `{ "capability": "<path>" }`.
///
/// Rejection is **diagnostics, not authorization**: returning this tells the peer
/// what it may not do; it never grants anything, and a host MUST NOT widen a grant
/// in response to receiving one.
pub const ERR_CAPABILITY_DENIED: i32 = -32002;
pub const ERR_UNKNOWN_FEATURE_SET: i32 = -32003;
pub const ERR_CHECKPOINT_NOT_FOUND: i32 = -32005;
pub const ERR_CHANNEL_NOT_PERMITTED: i32 = -32017;
pub const ERR_UNKNOWN_CHANNEL: i32 = -32023;
pub const ERR_CHANNEL_OPEN_FAILED: i32 = -32024;

/// Content block types (Appendix B.1 of MCPL spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    /// App. B.1 constrains image/audio with an inner `oneOf`: either
    /// `{data, mimeType}` **or** `{uri}`, never both and never neither. The
    /// exclusion is encoded in [`MediaSource`] rather than left to a runtime
    /// check, so `{data, uri}` and `{}` fail to deserialize instead of
    /// round-tripping.
    #[serde(rename = "image")]
    Image(MediaSource),
    #[serde(rename = "audio")]
    Audio(MediaSource),
    #[serde(rename = "resource")]
    Resource { uri: String },
}

/// The `oneOf` branch of an image or audio block (App. B.1).
///
/// `deny_unknown_fields` on each arm is what enforces the exclusion: a payload
/// carrying both `data` and `uri` matches neither arm, so the untagged enum
/// rejects it. `mimeType` is required alongside `data` (B.1's first branch
/// requires it) and optional alongside `uri` (B.1's second branch does not).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MediaSource {
    /// `{ "data": "...", "mimeType": "..." }`
    Inline(InlineMedia),
    /// `{ "uri": "..." }`, optionally with `mimeType`.
    Referenced(ReferencedMedia),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InlineMedia {
    pub data: String,
    /// Required alongside `data` by App. B.1's first branch.
    pub mime_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferencedMedia {
    pub uri: String,
    /// Optional alongside `uri`: App. B.1's second branch requires only `uri`,
    /// while `mimeType` remains a declared property.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl MediaSource {
    pub fn inline(data: impl Into<String>, mime_type: impl Into<String>) -> Self {
        MediaSource::Inline(InlineMedia {
            data: data.into(),
            mime_type: mime_type.into(),
        })
    }

    pub fn referenced(uri: impl Into<String>) -> Self {
        MediaSource::Referenced(ReferencedMedia {
            uri: uri.into(),
            mime_type: None,
        })
    }
}

impl ContentBlock {
    pub fn text(text: impl Into<String>) -> Self {
        ContentBlock::Text { text: text.into() }
    }

    pub fn image(source: MediaSource) -> Self {
        ContentBlock::Image(source)
    }

    pub fn audio(source: MediaSource) -> Self {
        ContentBlock::Audio(source)
    }

    pub fn resource(uri: impl Into<String>) -> Self {
        ContentBlock::Resource { uri: uri.into() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<ContentBlock, serde_json::Error> {
        serde_json::from_str(s)
    }

    #[test]
    fn image_accepts_exactly_one_of_data_or_uri() {
        assert!(parse(r#"{"type":"image","data":"AA==","mimeType":"image/png"}"#).is_ok());
        assert!(parse(r#"{"type":"image","uri":"https://example.test/a.png"}"#).is_ok());
        assert!(parse(
            r#"{"type":"image","uri":"https://example.test/a.png","mimeType":"image/png"}"#
        )
        .is_ok());
    }

    #[test]
    fn image_rejects_both_and_neither() {
        // Both present — App. B.1's `oneOf` is violated.
        assert!(parse(
            r#"{"type":"image","data":"AA==","mimeType":"image/png","uri":"https://x.test/a"}"#
        )
        .is_err());
        // Neither present.
        assert!(parse(r#"{"type":"image"}"#).is_err());
        // `data` without `mimeType` — B.1's first branch requires both.
        assert!(parse(r#"{"type":"image","data":"AA=="}"#).is_err());
    }

    #[test]
    fn audio_uses_the_same_exclusion() {
        assert!(parse(r#"{"type":"audio","data":"AA==","mimeType":"audio/ogg"}"#).is_ok());
        assert!(parse(r#"{"type":"audio","data":"AA==","mimeType":"audio/ogg","uri":"x"}"#).is_err());
    }

    #[test]
    fn blocks_round_trip() {
        for raw in [
            r#"{"type":"text","text":"hi"}"#,
            r#"{"type":"image","data":"AA==","mimeType":"image/png"}"#,
            r#"{"type":"audio","uri":"https://x.test/a.ogg"}"#,
            r#"{"type":"resource","uri":"file:///tmp/a"}"#,
        ] {
            let block: ContentBlock = parse(raw).unwrap();
            assert_eq!(
                serde_json::to_value(&block).unwrap(),
                serde_json::from_str::<serde_json::Value>(raw).unwrap(),
                "round-trip changed {raw}"
            );
        }
    }
}
