use mcpl_core::capabilities::*;
use mcpl_core::connection::{ConnectionError, McplConnection};
use mcpl_core::methods::*;
use mcpl_core::types::*;

use tokio::net::TcpListener;

/// Helper: spin up server + client connected over TCP.
async fn connected_pair() -> (McplConnection, McplConnection) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let client_fut = tokio::net::TcpStream::connect(addr);
    let server_fut = listener.accept();

    let (client_result, server_result) = tokio::join!(client_fut, server_fut);
    let client = McplConnection::new(client_result.unwrap());
    let (server_stream, _) = server_result.unwrap();
    let server = McplConnection::new(server_stream);
    (client, server)
}

#[tokio::test]
async fn test_capability_negotiation() {
    let (mut client, mut server) = connected_pair().await;

    // Client sends initialize request
    let client_caps = McplCapabilities {
        version: "0.4".into(),
        push_events: Some(true),
        channels: Some(true),
        rollback: Some(true),
        ..Default::default()
    };

    let init_params = McplInitializeParams {
        protocol_version: "2024-11-05".into(),
        capabilities: InitializeCapabilities {
            experimental: Some(ExperimentalCapabilities {
                mcpl: Some(client_caps),
            }),
            other: Default::default(),
        },
        client_info: ImplementationInfo {
            name: "test-client".into(),
            version: "0.1.0".into(),
        },
    };

    // Spawn client request
    let client_handle = tokio::spawn(async move {
        let result = client
            .send_request(
                method::INITIALIZE,
                Some(serde_json::to_value(&init_params).unwrap()),
            )
            .await
            .unwrap();
        let init_result: McplInitializeResult = serde_json::from_value(result).unwrap();
        (client, init_result)
    });

    // Server receives and responds
    let msg = server.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Request(req) => {
            assert_eq!(req.method, "initialize");
            let params: McplInitializeParams =
                serde_json::from_value(req.params.unwrap()).unwrap();
            assert_eq!(params.client_info.name, "test-client");

            let server_caps = McplCapabilities {
                version: "0.4".into(),
                push_events: Some(true),
                channels: Some(true),
                rollback: Some(true),
                feature_sets: Some(vec![
                    FeatureSetDeclaration {
                        name: "lobby".into(),
                        description: Some("Lobby operations".into()),
                        uses: vec!["connect".into(), "chat".into()],
                        rollback: false,
                        host_state: false,
                    },
                    FeatureSetDeclaration {
                        name: "game".into(),
                        description: Some("Game operations".into()),
                        uses: vec!["commands".into(), "observation".into()],
                        rollback: true,
                        host_state: false,
                    },
                ]),
                ..Default::default()
            };

            let result = McplInitializeResult {
                protocol_version: "2024-11-05".into(),
                capabilities: InitializeCapabilities {
                    experimental: Some(ExperimentalCapabilities {
                        mcpl: Some(server_caps),
                    }),
                    other: Default::default(),
                },
                server_info: ImplementationInfo {
                    name: "test-server".into(),
                    version: "0.1.0".into(),
                },
            };

            server
                .send_response(req.id, serde_json::to_value(&result).unwrap())
                .await
                .unwrap();
        }
        _ => panic!("Expected request"),
    }

    let (_client, init_result) = client_handle.await.unwrap();
    assert_eq!(init_result.server_info.name, "test-server");
    let mcpl = init_result
        .capabilities
        .experimental
        .unwrap()
        .mcpl
        .unwrap();
    assert!(mcpl.has_push_events());
    assert!(mcpl.has_channels());
    assert!(mcpl.has_rollback());
    let fs = mcpl.feature_sets.unwrap();
    assert_eq!(fs.len(), 2);
    assert_eq!(fs[0].name, "lobby");
    assert!(!fs[0].rollback);
    assert_eq!(fs[1].name, "game");
    assert!(fs[1].rollback);
}

#[tokio::test]
async fn test_notification_roundtrip() {
    let (mut client, mut server) = connected_pair().await;

    // Client sends notification
    let params = FeatureSetsUpdateParams {
        enabled: Some(vec!["lobby".into(), "game".into()]),
        disabled: None,
        scopes: None,
    };

    client
        .send_notification(
            method::FEATURE_SETS_UPDATE,
            Some(serde_json::to_value(&params).unwrap()),
        )
        .await
        .unwrap();

    // Server receives
    let msg = server.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Notification(notif) => {
            assert_eq!(notif.method, "featureSets/update");
            let p: FeatureSetsUpdateParams =
                serde_json::from_value(notif.params.unwrap()).unwrap();
            assert_eq!(p.enabled.unwrap(), vec!["lobby", "game"]);
        }
        _ => panic!("Expected notification"),
    }
}

#[tokio::test]
async fn test_push_event_request() {
    let (mut client, mut server) = connected_pair().await;

    // Server sends push/event request to client
    let event_params = PushEventParams {
        feature_set: "lobby".into(),
        event_id: "evt_001".into(),
        timestamp: "2026-02-12T00:00:00Z".into(),
        origin: None,
        payload: PushEventPayload {
            content: vec![ContentBlock::text("User joined lobby")],
        },
    };

    let server_handle = tokio::spawn(async move {
        let result = server
            .send_request(
                method::PUSH_EVENT,
                Some(serde_json::to_value(&event_params).unwrap()),
            )
            .await
            .unwrap();
        let push_result: PushEventResult = serde_json::from_value(result).unwrap();
        (server, push_result)
    });

    // Client receives and responds
    let msg = client.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Request(req) => {
            assert_eq!(req.method, "push/event");
            let p: PushEventParams = serde_json::from_value(req.params.unwrap()).unwrap();
            assert_eq!(p.feature_set, "lobby");
            assert_eq!(p.event_id, "evt_001");

            let result = PushEventResult {
                accepted: true,
                inference_id: Some("inf_001".into()),
                reason: None,
            };
            client
                .send_response(req.id, serde_json::to_value(&result).unwrap())
                .await
                .unwrap();
        }
        _ => panic!("Expected request"),
    }

    let (_server, push_result) = server_handle.await.unwrap();
    assert!(push_result.accepted);
    assert_eq!(push_result.inference_id.unwrap(), "inf_001");
}

#[tokio::test]
async fn test_channel_lifecycle() {
    let (mut client, mut server) = connected_pair().await;

    // Server registers channels
    let reg_params = ChannelsRegisterParams {
        channels: vec![ChannelDescriptor {
            id: "game".into(),
            channel_type: "game_instance".into(),
            label: "Game Instances".into(),
            direction: ChannelDirection::Bidirectional,
            address: None,
            metadata: None,
        }],
    };

    let server_handle = tokio::spawn(async move {
        let _result = server
            .send_request(
                method::CHANNELS_REGISTER,
                Some(serde_json::to_value(&reg_params).unwrap()),
            )
            .await
            .unwrap();
        server
    });

    // Client receives register request
    let msg = client.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Request(req) => {
            assert_eq!(req.method, "channels/register");
            let p: ChannelsRegisterParams =
                serde_json::from_value(req.params.unwrap()).unwrap();
            assert_eq!(p.channels.len(), 1);
            assert_eq!(p.channels[0].id, "game");

            client
                .send_response(req.id, serde_json::json!({}))
                .await
                .unwrap();
        }
        _ => panic!("Expected request"),
    }

    let mut server = server_handle.await.unwrap();

    // Client opens a channel
    let open_params = ChannelsOpenParams {
        channel_type: "game_instance".into(),
        address: serde_json::json!({"map": "DeltaSiegeDry", "mod": "Zero-K v1.12"}),
        metadata: None,
    };

    let client_handle = tokio::spawn(async move {
        let result = client
            .send_request(
                method::CHANNELS_OPEN,
                Some(serde_json::to_value(&open_params).unwrap()),
            )
            .await
            .unwrap();
        let open_result: ChannelsOpenResult = serde_json::from_value(result).unwrap();
        (client, open_result)
    });

    let msg = server.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Request(req) => {
            assert_eq!(req.method, "channels/open");

            let result = ChannelsOpenResult {
                channel: ChannelDescriptor {
                    id: "game:live-1".into(),
                    channel_type: "game_instance".into(),
                    label: "Live Game 1".into(),
                    direction: ChannelDirection::Bidirectional,
                    address: Some(serde_json::json!({"map": "DeltaSiegeDry"})),
                    metadata: None,
                },
            };

            server
                .send_response(req.id, serde_json::to_value(&result).unwrap())
                .await
                .unwrap();
        }
        _ => panic!("Expected request"),
    }

    let (_client, open_result) = client_handle.await.unwrap();
    assert_eq!(open_result.channel.id, "game:live-1");
    assert_eq!(open_result.channel.label, "Live Game 1");
}

#[tokio::test]
async fn test_error_response() {
    let (mut client, mut server) = connected_pair().await;

    let client_handle = tokio::spawn(async move {
        let err = client
            .send_request(method::STATE_ROLLBACK, Some(serde_json::json!({"featureSet": "game", "checkpoint": "nonexistent"})))
            .await
            .unwrap_err();
        (client, err)
    });

    let msg = server.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Request(req) => {
            server
                .send_error(req.id, ERR_CHECKPOINT_NOT_FOUND, "Checkpoint not found")
                .await
                .unwrap();
        }
        _ => panic!("Expected request"),
    }

    let (_client, err) = client_handle.await.unwrap();
    match err {
        mcpl_core::connection::ConnectionError::Rpc { code, message } => {
            assert_eq!(code, ERR_CHECKPOINT_NOT_FOUND);
            assert_eq!(message, "Checkpoint not found");
        }
        other => panic!("Expected RPC error, got: {:?}", other),
    }
}

#[tokio::test]
async fn test_content_block_serialization() {
    let text = ContentBlock::text("Hello");
    let json = serde_json::to_value(&text).unwrap();
    assert_eq!(json, serde_json::json!({"type": "text", "text": "Hello"}));

    let image = ContentBlock::Image {
        data: Some("base64data".into()),
        uri: None,
        mime_type: Some("image/png".into()),
    };
    let json = serde_json::to_value(&image).unwrap();
    assert_eq!(
        json,
        serde_json::json!({"type": "image", "data": "base64data", "mimeType": "image/png"})
    );

    // Roundtrip
    let deserialized: ContentBlock = serde_json::from_value(json).unwrap();
    match deserialized {
        ContentBlock::Image { data, uri, mime_type } => {
            assert_eq!(data.unwrap(), "base64data");
            assert!(uri.is_none());
            assert_eq!(mime_type.unwrap(), "image/png");
        }
        _ => panic!("Expected Image"),
    }
}

#[tokio::test]
async fn test_from_parts() {
    // from_parts with tokio::io::duplex simulates stdio/pipe transport
    let (client_read, server_write) = tokio::io::duplex(4096);
    let (server_read, client_write) = tokio::io::duplex(4096);

    let mut client = McplConnection::from_parts(
        Box::new(client_read),
        Box::new(client_write),
    );
    let mut server = McplConnection::from_parts(
        Box::new(server_read),
        Box::new(server_write),
    );

    // Send a notification through the pipe
    client
        .send_notification("test/hello", Some(serde_json::json!({"from": "client"})))
        .await
        .unwrap();

    let msg = server.next_message().await.unwrap();
    match msg {
        mcpl_core::connection::IncomingMessage::Notification(notif) => {
            assert_eq!(notif.method, "test/hello");
            let p: serde_json::Value = notif.params.unwrap();
            assert_eq!(p["from"], "client");
        }
        _ => panic!("Expected notification"),
    }
}

#[tokio::test]
async fn test_close_returns_error() {
    let (client_read, _server_write) = tokio::io::duplex(4096);
    let (_server_read, client_write) = tokio::io::duplex(4096);

    let mut client = McplConnection::from_parts(
        Box::new(client_read),
        Box::new(client_write),
    );

    // Drop server side — client should get Closed on next_message
    drop(_server_write);

    let err = client.next_message().await.unwrap_err();
    assert!(matches!(err, ConnectionError::Closed));
}

#[tokio::test]
async fn test_incoming_messages_buffered_during_send_request() {
    let (mut client, mut server) = connected_pair().await;

    // Server sends a request to the client (which the client hasn't called
    // next_message for), then the client sends its own request. The server's
    // request should be buffered and available after the client's request
    // completes.

    // 1. Client sends a request
    let client_handle = tokio::spawn(async move {
        let result = client
            .send_request("test/echo", Some(serde_json::json!({"n": 1})))
            .await
            .unwrap();
        (client, result)
    });

    // 2. Server receives the client's request
    let msg = server.next_message().await.unwrap();
    let req_id = match &msg {
        mcpl_core::connection::IncomingMessage::Request(req) => {
            assert_eq!(req.method, "test/echo");
            req.id.clone()
        }
        _ => panic!("Expected request"),
    };

    // 3. Before responding, server fires a push event AT the client
    //    This message arrives while client is blocked in send_request
    let event_params = PushEventParams {
        feature_set: "game".into(),
        event_id: "tick_42".into(),
        timestamp: "2026-02-12T00:00:00Z".into(),
        origin: None,
        payload: PushEventPayload {
            content: vec![ContentBlock::text("Game tick 42")],
        },
    };
    // Send as a notification (doesn't need response) to avoid deadlock
    server
        .send_notification(
            method::PUSH_EVENT,
            Some(serde_json::to_value(&event_params).unwrap()),
        )
        .await
        .unwrap();

    // 4. Now server responds to the original request
    server
        .send_response(req_id, serde_json::json!({"echo": true}))
        .await
        .unwrap();

    // 5. Client gets its response
    let (mut client, result) = client_handle.await.unwrap();
    assert_eq!(result["echo"], true);

    // 6. The push event notification should be available via next_message
    //    (buffered, not dropped!)
    let buffered = client.next_message().await.unwrap();
    match buffered {
        mcpl_core::connection::IncomingMessage::Notification(notif) => {
            assert_eq!(notif.method, method::PUSH_EVENT);
            let p: PushEventParams =
                serde_json::from_value(notif.params.unwrap()).unwrap();
            assert_eq!(p.event_id, "tick_42");
        }
        _ => panic!("Expected buffered notification, got request"),
    }
}
