use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

use crate::types::*;

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Connection closed")]
    Closed,
    #[error("Request timed out")]
    Timeout,
    #[error("RPC error {code}: {message}")]
    Rpc { code: i32, message: String },
    #[error("Unexpected response for id {0:?}")]
    UnexpectedResponse(JsonRpcId),
}

/// Incoming message from the remote side — either a request/notification that
/// needs handling, or a response to one of our pending requests.
#[derive(Debug)]
pub enum IncomingMessage {
    Request(JsonRpcRequest),
    Notification(JsonRpcNotification),
}

/// Bidirectional async JSON-RPC 2.0 connection.
///
/// Messages are framed as newline-delimited JSON (one JSON object per line).
/// Transport-agnostic: works over TCP, stdio, or any async reader/writer pair.
pub struct McplConnection {
    writer: Box<dyn AsyncWrite + Unpin + Send>,
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    next_id: AtomicI64,
    pending: HashMap<JsonRpcId, oneshot::Sender<JsonRpcResponse>>,
}

impl McplConnection {
    /// Create from a TCP stream.
    pub fn new(stream: TcpStream) -> Self {
        Self::from_tcp(stream)
    }

    /// Create from a TCP stream (explicit name).
    pub fn from_tcp(stream: TcpStream) -> Self {
        let (read_half, write_half) = stream.into_split();
        Self {
            writer: Box::new(write_half),
            reader: BufReader::new(Box::new(read_half) as Box<dyn AsyncRead + Unpin + Send>),
            next_id: AtomicI64::new(1),
            pending: HashMap::new(),
        }
    }

    /// Create from arbitrary async reader/writer (e.g., stdin/stdout).
    pub fn from_parts(
        reader: Box<dyn AsyncRead + Unpin + Send>,
        writer: Box<dyn AsyncWrite + Unpin + Send>,
    ) -> Self {
        Self {
            writer,
            reader: BufReader::new(reader),
            next_id: AtomicI64::new(1),
            pending: HashMap::new(),
        }
    }

    /// Send a JSON-RPC request and wait for the response.
    pub async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, ConnectionError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = JsonRpcRequest::new(id, method, params);

        let (tx, _rx) = oneshot::channel();
        self.pending.insert(JsonRpcId::Number(id), tx);

        self.write_message(&JsonRpcMessage::Request(request)).await?;

        // Drive reads until we get our response
        loop {
            match self.read_next_internal().await? {
                InternalMessage::Response(resp) => {
                    if resp.id == JsonRpcId::Number(id) {
                        if let Some(error) = resp.error {
                            return Err(ConnectionError::Rpc {
                                code: error.code,
                                message: error.message,
                            });
                        }
                        return Ok(resp.result.unwrap_or(serde_json::Value::Null));
                    }
                    // Response for a different request — route it
                    if let Some(sender) = self.pending.remove(&resp.id) {
                        let _ = sender.send(resp);
                    }
                }
                InternalMessage::Incoming(msg) => {
                    // We got an incoming request/notification while waiting for our response.
                    // In a simple single-task usage this shouldn't happen, but for robustness
                    // we could buffer these. For now, log and drop.
                    tracing::warn!("Received incoming message while waiting for response: {:?}", msg);
                }
            }
        }
    }

    /// Send a JSON-RPC notification (no response expected).
    pub async fn send_notification(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<(), ConnectionError> {
        let notification = JsonRpcNotification::new(method, params);
        self.write_message(&JsonRpcMessage::Notification(notification)).await
    }

    /// Send a JSON-RPC response (answering an incoming request).
    pub async fn send_response(
        &mut self,
        id: JsonRpcId,
        result: serde_json::Value,
    ) -> Result<(), ConnectionError> {
        let response = JsonRpcResponse::success(id, result);
        self.write_message(&JsonRpcMessage::Response(response)).await
    }

    /// Send a JSON-RPC error response.
    pub async fn send_error(
        &mut self,
        id: JsonRpcId,
        code: i32,
        message: impl Into<String>,
    ) -> Result<(), ConnectionError> {
        let response = JsonRpcResponse::error(
            id,
            JsonRpcError {
                code,
                message: message.into(),
                data: None,
            },
        );
        self.write_message(&JsonRpcMessage::Response(response)).await
    }

    /// Read the next incoming request or notification.
    /// Responses to our pending requests are routed internally.
    pub async fn next_message(&mut self) -> Result<IncomingMessage, ConnectionError> {
        loop {
            match self.read_next_internal().await? {
                InternalMessage::Response(resp) => {
                    if let Some(sender) = self.pending.remove(&resp.id) {
                        let _ = sender.send(resp);
                    }
                }
                InternalMessage::Incoming(msg) => return Ok(msg),
            }
        }
    }

    async fn write_message(&mut self, msg: &JsonRpcMessage) -> Result<(), ConnectionError> {
        let mut line = serde_json::to_string(msg)?;
        line.push('\n');
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn read_next_internal(&mut self) -> Result<InternalMessage, ConnectionError> {
        loop {
            let mut line = String::new();
            let bytes_read = self.reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                return Err(ConnectionError::Closed);
            }

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // JSON-RPC distinguishes by presence of `id` and `method`:
            //   Request:      has `id` + `method`
            //   Response:     has `id` + (`result` or `error`)
            //   Notification: has `method`, no `id`
            let value: serde_json::Value = serde_json::from_str(trimmed)?;

            let has_id = value.get("id").is_some();
            let has_method = value.get("method").is_some();
            let has_result = value.get("result").is_some();
            let has_error = value.get("error").is_some();

            if has_id && has_method {
                let request: JsonRpcRequest = serde_json::from_value(value)?;
                return Ok(InternalMessage::Incoming(IncomingMessage::Request(request)));
            } else if has_id && (has_result || has_error) {
                let response: JsonRpcResponse = serde_json::from_value(value)?;
                return Ok(InternalMessage::Response(response));
            } else if has_method && !has_id {
                let notification: JsonRpcNotification = serde_json::from_value(value)?;
                return Ok(InternalMessage::Incoming(IncomingMessage::Notification(notification)));
            } else {
                tracing::warn!("Unrecognized JSON-RPC message: {}", trimmed);
                return Err(ConnectionError::Json(
                    serde_json::from_str::<()>(trimmed).unwrap_err(),
                ));
            }
        }
    }
}

enum InternalMessage {
    Response(JsonRpcResponse),
    Incoming(IncomingMessage),
}
