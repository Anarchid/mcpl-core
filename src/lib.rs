//! MCPL v0.5 wire protocol types and async transport.
//!
//! Layout mirrors the specification:
//!
//! - [`types`] — JSON-RPC framing, error codes, `ContentBlock` (App. B.1)
//! - [`capabilities`] — the `experimental.mcpl` advertisement / manifest (§5.1)
//! - [`grant`] — capability paths, recursive expansion, the grant (§5.4, §6.2, §6.4)
//! - [`manifest`] — manifest changes and the canonical digest (§17)
//! - [`tags`] — event tags and the producer ontology (§16 / RFC-001)
//! - [`methods`] — request/response/notification parameter types
//! - [`connection`] — newline-delimited JSON-RPC transport

pub mod capabilities;
pub mod connection;
pub mod grant;
pub mod manifest;
pub mod methods;
pub mod tags;
pub mod types;

pub use capabilities::*;
pub use connection::McplConnection;
pub use grant::*;
pub use manifest::*;
pub use methods::*;
// `tags::chat` stays module-qualified (`tags::chat::MENTION`) — glob-exporting a
// module named `chat` at the crate root would be worse than the qualification.
pub use tags::{
    expand_core_closure, is_namespaced, is_reserved, namespace, KeyedTagFamily, TagDescriptor,
    TagFacet, TagOntology, TagStability, TreatmentRule, RESERVED_NAMESPACES,
};
pub use types::*;
