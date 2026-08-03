//! Capability paths, recursive advertisement expansion, and the capability grant
//! (SPEC §5.1, §5.4, §6.2, §6.4).
//!
//! The grant is the security boundary. Feature sets derive from it and carry no
//! authority of their own.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::methods::FeatureSetDeclaration;

/// The closed capability-path vocabulary (SPEC §6.2, Appendix B.2).
///
/// This list is normative and exhaustive. `uses` MUST contain only these values.
/// Nothing may be added here without a spec change.
pub const CAPABILITY_PATHS: &[&str] = &[
    "pushEvents",
    "tools",
    "modelInfo",
    "inferenceRequest",
    "inferenceRequest.streaming",
    "inferenceLifecycle",
    "contextHooks.beforeInference.observe",
    "contextHooks.beforeInference.inject.system",
    "contextHooks.beforeInference.inject.beforeUser",
    "contextHooks.beforeInference.inject.afterUser",
    "channels.register",
    "channels.lifecycle",
    "channels.publish",
    "channels.incoming",
    "channels.streaming",
    "channels.acknowledge",
    "channels.typing",
];

/// True if `path` is a member of the closed §6.2 vocabulary.
pub fn is_capability_path(path: &str) -> bool {
    CAPABILITY_PATHS.contains(&path)
}

/// Capability paths that are *never* advertised inside `experimental.mcpl`.
///
/// `tools` is a standard MCP capability (`capabilities.tools`), not an MCPL member,
/// so [`advertised_capabilities`] can never derive it from the MCPL manifest alone.
/// A host that wants to grant `tools` must add it from the MCP capabilities object.
pub const PATHS_NOT_ADVERTISED_IN_MCPL: &[&str] = &["tools"];

/// The capability required to send a channel method (SPEC §14.1).
///
/// Channel methods are authorized by the connection grant keyed on **method and
/// channel id** — *not* by a `featureSet` field, which channel methods do not
/// carry. Feature sets MAY still name these paths in `uses` for ergonomics and
/// honest degradation reporting (§6.4), but they are not the authorization.
///
/// `None` means this table does not settle the method. §14.1 is the only
/// method→capability table the specification states in this form, so no mapping is
/// invented for the other method families. `None` is **not** permission: a caller
/// that cannot establish a required capability must deny.
pub fn channel_method_capability(method: &str) -> Option<&'static str> {
    Some(match method {
        "channels/register" | "channels/changed" | "channels/list" => "channels.register",
        "channels/open" | "channels/close" => "channels.lifecycle",
        "channels/publish" => "channels.publish",
        "channels/incoming" => "channels.incoming",
        "channels/outgoing/chunk" | "channels/outgoing/complete" => "channels.streaming",
        "channels/acknowledge" => "channels.acknowledge",
        "channels/typing" => "channels.typing",
        _ => return None,
    })
}

// ── Recursive advertisement expansion (§5.1) ──────────────────────────────────

/// Expand a server's (or host's) `experimental.mcpl` advertisement into the set of
/// capability paths it claims (SPEC §5.1).
///
/// This is a **generic recursive walk** over the advertised JSON, as §5.4 requires:
/// there is no hardcoded list of nestable keys, only the closed §6.2 vocabulary used
/// as the set of recognised leaves.
///
/// Rules:
/// - `true` at any node is shorthand for *every leaf beneath that node* (and for the
///   node itself when the node is a capability path in its own right).
/// - `false` or absence contributes nothing.
/// - An object recurses into its members. If the object's own path is a capability
///   path, that path is also contributed — an object at `inferenceRequest` means
///   inference requests are advertised, otherwise `inferenceRequest.streaming` could
///   be advertised without its base.
/// - Members that are not part of the §6.2 vocabulary (`version`, `revision`,
///   `featureSets`, and any extension member) contribute nothing. Advertisement
///   cannot mint a path the vocabulary does not contain.
/// - Paths in [`PATHS_NOT_ADVERTISED_IN_MCPL`] (`tools`) contribute nothing even
///   when literally present: SPEC §5.1 places `tools` only in standard MCP
///   `capabilities.tools`, so `experimental.mcpl` can never mint it. A caller may
///   add `tools` only from the outer MCP handshake.
///
/// The result is an *advertisement*, never an authorization: the host intersects it
/// with policy to produce the grant (§5.4).
pub fn advertised_capabilities(mcpl: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(obj) = mcpl.as_object() {
        for (key, value) in obj {
            walk_advertisement(key, value, &mut out);
        }
    }
    out
}

fn walk_advertisement(path: &str, value: &serde_json::Value, out: &mut BTreeSet<String>) {
    // Prune anything that cannot lead to a known leaf. This is what keeps
    // `version`, `revision`, `featureSets` and extension members out.
    if !is_capability_path(path) && !has_descendant_paths(path) {
        return;
    }
    // Paths that live in the outer MCP handshake (`tools`) are never derivable
    // from `experimental.mcpl`, even when literally present (SPEC §5.1).
    if PATHS_NOT_ADVERTISED_IN_MCPL.contains(&path) {
        return;
    }

    match value {
        serde_json::Value::Bool(true) => {
            if is_capability_path(path) {
                out.insert(path.to_string());
            }
            for leaf in descendant_paths(path) {
                if !PATHS_NOT_ADVERTISED_IN_MCPL.contains(leaf) {
                    out.insert(leaf.to_string());
                }
            }
        }
        serde_json::Value::Object(obj) => {
            if is_capability_path(path) {
                out.insert(path.to_string());
            }
            for (key, child) in obj {
                let child_path = format!("{path}.{key}");
                walk_advertisement(&child_path, child, out);
            }
        }
        // `false`, null, and any non-conforming scalar advertise nothing.
        _ => {}
    }
}

fn has_descendant_paths(prefix: &str) -> bool {
    let with_dot = format!("{prefix}.");
    CAPABILITY_PATHS.iter().any(|p| p.starts_with(&with_dot))
}

fn descendant_paths(prefix: &str) -> impl Iterator<Item = &'static &'static str> {
    let with_dot = format!("{prefix}.");
    CAPABILITY_PATHS
        .iter()
        .filter(move |p| p.starts_with(&with_dot))
}

// ── The capability grant (§5.4) ───────────────────────────────────────────────

/// The JSON-RPC carrier of a `featureSets/update` (SPEC §6.7).
///
/// The form is authorization-relevant, not a transport detail: only a Request —
/// which the host must answer with a receipt — can alter the effective grant. See
/// [`CapabilityGrant::from_update`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateForm {
    /// Carries an `id` and is answered by a degradation receipt. Required for any
    /// change to the effective grant, including the initial policy (§5.3).
    Request,
    /// Unacknowledged. Valid only for purely descriptive feature metadata; cannot
    /// alter the grant or establish a ready state.
    Notification,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum GrantError {
    /// §5.4: "If a path appears in both, the receiving side MUST fail closed and
    /// reject the policy message as malformed."
    #[error("capability path appears in both effectiveCapabilities and deniedCapabilities: {0}")]
    PathInBothLists(String),
}

/// The effective capability grant for a connection (SPEC §5.4).
///
/// `effectiveCapabilities` is the **sole normative allowlist**. Every path not
/// present is denied; absence *is* the denial. `deniedCapabilities` is diagnostic
/// data only and never participates in an authorization decision — it is not stored
/// here, deliberately.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapabilityGrant {
    entries: BTreeSet<String>,
}

impl CapabilityGrant {
    /// The empty grant: everything is denied. This is the correct state before the
    /// initial policy exchange completes (§5.3).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a grant from an `effectiveCapabilities` list alone.
    pub fn from_effective<I, S>(effective: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            entries: effective.into_iter().map(Into::into).collect(),
        }
    }

    /// Build a grant from a `featureSets/update` policy message, applying the §5.4
    /// fail-closed check that no path appears in both lists.
    ///
    /// The meaning of an absent `effectiveCapabilities` depends on the JSON-RPC
    /// **form** the message arrived in (§6.7), so the caller must say which:
    ///
    /// - [`UpdateForm::Request`] is a change to the effective grant, and the
    ///   allowlist is total: absent `effectiveCapabilities` is a grant of
    ///   **nothing** — `Ok(Some(empty))`, deny-all. Treating it as no-alteration
    ///   would leave a stale wider grant standing, the §6.7 hole class.
    /// - [`UpdateForm::Notification`] never alters the grant — `Ok(None)`,
    ///   regardless of what the message carries. §6.7 (pinned 2026-08-02): a
    ///   non-conforming Notification's `effectiveCapabilities`, `enabled`, and any
    ///   widening are discarded with a diagnostic, because honouring them would
    ///   have the server acting on a path the host cannot know it accepted; only a
    ///   narrowing `disabled` list is respected, and that is a *feature-set*
    ///   reduction applied by the caller, not a grant alteration. A Notification
    ///   MUST NOT establish a ready state.
    pub fn from_update(
        params: &crate::methods::FeatureSetsUpdateParams,
        form: UpdateForm,
    ) -> Result<Option<Self>, GrantError> {
        if form == UpdateForm::Notification {
            return Ok(None);
        }
        let Some(effective) = params.effective_capabilities.as_ref() else {
            // Request form: the absent allowlist grants nothing (§5.4: absence is
            // the denial), it does not preserve the previous grant.
            return Ok(Some(Self::empty()));
        };
        if let Some(denied) = params.denied_capabilities.as_ref() {
            let denied_set: BTreeSet<&str> = denied.iter().map(String::as_str).collect();
            for path in effective {
                if denied_set.contains(path.as_str()) {
                    return Err(GrantError::PathInBothLists(path.clone()));
                }
            }
        }
        Ok(Some(Self::from_effective(effective.iter().cloned())))
    }

    /// Every entry in the grant, including any wildcard patterns.
    pub fn entries(&self) -> &BTreeSet<String> {
        &self.entries
    }

    /// Whether `path` is granted.
    ///
    /// Matching is over full dot-separated paths. A grant entry may contain `*`,
    /// which matches **exactly one** path segment (`channels.*` grants
    /// `channels.publish` but not a hypothetical `channels.publish.thread`). The
    /// spec says only "full paths with `*` wildcards" and does not define multi-
    /// segment matching, so the narrower reading is used.
    ///
    /// Absence is denial. There is no default-allow branch in this function.
    pub fn allows(&self, path: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| path_matches(entry.as_str(), path))
    }

    /// Whether every path in `required` is granted.
    pub fn allows_all<'a, I: IntoIterator<Item = &'a str>>(&self, required: I) -> bool {
        required.into_iter().all(|p| self.allows(p))
    }

    /// The subset of `required` that is *not* granted, in input order.
    pub fn missing<'a, I: IntoIterator<Item = &'a str>>(&self, required: I) -> Vec<String> {
        required
            .into_iter()
            .filter(|p| !self.allows(p))
            .map(str::to_string)
            .collect()
    }
}

fn path_matches(pattern: &str, path: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == path;
    }
    let mut pattern_segments = pattern.split('.');
    let mut path_segments = path.split('.');
    loop {
        match (pattern_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(p), Some(s)) if p == "*" || p == s => continue,
            _ => return false,
        }
    }
}

// ── Feature-set derivation (§6.4) ─────────────────────────────────────────────

/// Why a declared feature set is not enabled (SPEC §6.4, §6.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum DisabledReason {
    /// §6.2/§6.4 rule 1: `uses` is absent, empty, or names something outside the
    /// closed vocabulary. The host does not guess what it meant.
    InvalidUses {
        /// The offending entries, if the failure was an unrecognised value rather
        /// than absence/emptiness.
        #[serde(rename = "unrecognized", skip_serializing_if = "Vec::is_empty", default)]
        unrecognized: Vec<String>,
    },
    /// Every `uses` entry is recognised, but at least one is not in the grant.
    MissingCapabilities {
        #[serde(rename = "missingCapabilities")]
        missing: Vec<String>,
    },
}

/// The derived status of one declared feature set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeatureSetStatus {
    Enabled,
    Disabled(DisabledReason),
}

impl FeatureSetStatus {
    pub fn is_enabled(&self) -> bool {
        matches!(self, FeatureSetStatus::Enabled)
    }
}

/// Validate a `uses` list against the closed §6.2 vocabulary.
///
/// An absent `uses` deserialises to an empty vector, and §6.2 makes absent and empty
/// equally invalid, so both land here as `InvalidUses`.
pub fn validate_uses(uses: &[String]) -> Result<(), DisabledReason> {
    if uses.is_empty() {
        return Err(DisabledReason::InvalidUses {
            unrecognized: Vec::new(),
        });
    }
    let unrecognized: Vec<String> = uses
        .iter()
        .filter(|u| !is_capability_path(u))
        .cloned()
        .collect();
    if unrecognized.is_empty() {
        Ok(())
    } else {
        Err(DisabledReason::InvalidUses { unrecognized })
    }
}

/// Derive one feature set's status from the grant (SPEC §6.4). Fail-closed:
/// an invalid declaration is disabled, and a valid declaration naming any
/// ungranted capability is disabled.
///
/// Note rule 2 of §6.4: a *valid but incomplete* `uses` does not weaken anything.
/// Security is the grant, checked at use, not the declaration.
pub fn derive_feature_set(
    decl: &FeatureSetDeclaration,
    grant: &CapabilityGrant,
) -> FeatureSetStatus {
    if let Err(reason) = validate_uses(&decl.uses) {
        return FeatureSetStatus::Disabled(reason);
    }
    let missing = grant.missing(decl.uses.iter().map(String::as_str));
    if missing.is_empty() {
        FeatureSetStatus::Enabled
    } else {
        FeatureSetStatus::Disabled(DisabledReason::MissingCapabilities { missing })
    }
}

/// Derive every declared feature set's status from the grant (SPEC §6.4).
pub fn derive_feature_sets(
    declarations: &BTreeMap<String, FeatureSetDeclaration>,
    grant: &CapabilityGrant,
) -> BTreeMap<String, FeatureSetStatus> {
    declarations
        .iter()
        .map(|(name, decl)| (name.clone(), derive_feature_set(decl, grant)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn boolean_true_is_shorthand_for_every_leaf_beneath() {
        let adv = advertised_capabilities(&json!({
            "version": "0.5",
            "contextHooks": { "beforeInference": true }
        }));
        assert_eq!(
            adv.iter().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "contextHooks.beforeInference.inject.afterUser",
                "contextHooks.beforeInference.inject.beforeUser",
                "contextHooks.beforeInference.inject.system",
                "contextHooks.beforeInference.observe",
            ]
        );
    }

    #[test]
    fn recursive_walk_honours_per_leaf_false() {
        let adv = advertised_capabilities(&json!({
            "contextHooks": {
                "beforeInference": {
                    "observe": true,
                    "inject": { "system": false, "beforeUser": true, "afterUser": true }
                }
            }
        }));
        assert!(adv.contains("contextHooks.beforeInference.observe"));
        assert!(adv.contains("contextHooks.beforeInference.inject.beforeUser"));
        assert!(adv.contains("contextHooks.beforeInference.inject.afterUser"));
        assert!(!adv.contains("contextHooks.beforeInference.inject.system"));
    }

    #[test]
    fn non_vocabulary_members_advertise_nothing() {
        let adv = advertised_capabilities(&json!({
            "version": "0.5",
            "revision": "sha256:whatever",
            "featureSets": { "a.b": { "description": "d", "uses": ["tools"] } },
            "somethingInvented": true,
            "contextHooks": { "afterInference": true }
        }));
        assert!(adv.is_empty(), "unexpected paths: {adv:?}");
    }

    #[test]
    fn inference_request_object_advertises_its_own_path() {
        let adv = advertised_capabilities(&json!({ "inferenceRequest": { "streaming": true } }));
        assert!(adv.contains("inferenceRequest"));
        assert!(adv.contains("inferenceRequest.streaming"));

        let adv = advertised_capabilities(&json!({ "inferenceRequest": { "streaming": false } }));
        assert!(adv.contains("inferenceRequest"));
        assert!(!adv.contains("inferenceRequest.streaming"));
    }

    #[test]
    fn channels_true_expands_to_all_seven_leaves() {
        let adv = advertised_capabilities(&json!({ "channels": true }));
        assert_eq!(adv.len(), 7);
        assert!(adv.contains("channels.streaming"));
        assert!(adv.contains("channels.acknowledge"));
        assert!(adv.contains("channels.typing"));
    }

    #[test]
    fn tools_is_never_advertised_from_the_mcpl_manifest() {
        // `tools` lives in MCP `capabilities.tools`, not in `experimental.mcpl`
        // (SPEC §5.1). Even a literal `"tools": true` in the MCPL manifest mints
        // nothing; only the outer MCP handshake can contribute it.
        let adv = advertised_capabilities(&json!({ "tools": true }));
        assert!(adv.is_empty(), "unexpected paths: {adv:?}");

        let adv = advertised_capabilities(&json!({ "tools": { "anything": true } }));
        assert!(adv.is_empty(), "unexpected paths: {adv:?}");

        assert!(PATHS_NOT_ADVERTISED_IN_MCPL.contains(&"tools"));
    }

    #[test]
    fn absence_is_denial() {
        let grant = CapabilityGrant::from_effective(["channels.publish"]);
        assert!(grant.allows("channels.publish"));
        assert!(!grant.allows("channels.incoming"));
        assert!(!CapabilityGrant::empty().allows("pushEvents"));
    }

    #[test]
    fn wildcard_matches_exactly_one_segment() {
        let grant = CapabilityGrant::from_effective(["channels.*"]);
        assert!(grant.allows("channels.publish"));
        assert!(!grant.allows("channels.publish.thread"));
        assert!(!grant.allows("pushEvents"));
    }

    #[test]
    fn path_in_both_lists_is_malformed() {
        let params = crate::methods::FeatureSetsUpdateParams {
            effective_capabilities: Some(vec!["tools".into(), "channels.publish".into()]),
            denied_capabilities: Some(vec!["channels.publish".into()]),
            enabled: None,
            disabled: None,
        };
        assert_eq!(
            CapabilityGrant::from_update(&params, UpdateForm::Request),
            Err(GrantError::PathInBothLists("channels.publish".into()))
        );
    }

    #[test]
    fn request_without_effective_capabilities_grants_nothing() {
        // §6.7: the Request form is a change to the effective grant and the
        // allowlist is total — absence is deny-all, never "keep the old grant".
        let params = crate::methods::FeatureSetsUpdateParams {
            effective_capabilities: None,
            denied_capabilities: None,
            enabled: None,
            disabled: None,
        };
        let grant = CapabilityGrant::from_update(&params, UpdateForm::Request)
            .unwrap()
            .expect("a Request always yields a grant");
        assert_eq!(grant, CapabilityGrant::empty());
        assert!(!grant.allows("channels.publish"));
    }

    #[test]
    fn descriptive_notification_without_effective_capabilities_alters_nothing() {
        let params = crate::methods::FeatureSetsUpdateParams {
            effective_capabilities: None,
            denied_capabilities: None,
            enabled: Some(vec!["memory.retrieval".into()]),
            disabled: None,
        };
        assert_eq!(
            CapabilityGrant::from_update(&params, UpdateForm::Notification),
            Ok(None)
        );
    }

    #[test]
    fn notification_never_alters_the_grant() {
        // §6.7 (pinned 2026-08-02): a non-conforming Notification carrying
        // `effectiveCapabilities` is discarded with a diagnostic — honouring a
        // widening from an unacknowledgeable message would have the server acting
        // on a path the host cannot know it accepted. Only a narrowing `disabled`
        // list is respected, at the feature-set level, by the caller.
        let params = crate::methods::FeatureSetsUpdateParams {
            effective_capabilities: Some(vec!["channels.publish".into(), "tools".into()]),
            denied_capabilities: None,
            enabled: Some(vec!["memory.retrieval".into()]),
            disabled: Some(vec!["memory.extraction".into()]),
        };
        assert_eq!(
            CapabilityGrant::from_update(&params, UpdateForm::Notification),
            Ok(None)
        );
    }

    #[test]
    fn empty_or_unrecognized_uses_is_invalid() {
        assert!(matches!(
            validate_uses(&[]),
            Err(DisabledReason::InvalidUses { .. })
        ));
        // §6.1's example still writes `contextHooks.beforeInference`, but §6.2 and
        // App. B.2 list only the four leaves. The closed list wins.
        assert!(matches!(
            validate_uses(&["contextHooks.beforeInference".to_string()]),
            Err(DisabledReason::InvalidUses { .. })
        ));
        assert!(validate_uses(&["contextHooks.beforeInference.observe".to_string()]).is_ok());
    }

    #[test]
    fn channel_methods_map_to_the_1441_table() {
        for (method, expected) in [
            ("channels/register", "channels.register"),
            ("channels/changed", "channels.register"),
            ("channels/list", "channels.register"),
            ("channels/open", "channels.lifecycle"),
            ("channels/close", "channels.lifecycle"),
            ("channels/publish", "channels.publish"),
            ("channels/incoming", "channels.incoming"),
            ("channels/outgoing/chunk", "channels.streaming"),
            ("channels/outgoing/complete", "channels.streaming"),
            ("channels/acknowledge", "channels.acknowledge"),
            ("channels/typing", "channels.typing"),
        ] {
            assert_eq!(channel_method_capability(method), Some(expected), "{method}");
            assert!(is_capability_path(expected), "{expected} is not in §6.2");
        }
        // Not in §14.1's table; no mapping is invented, and `None` is not permission.
        assert_eq!(channel_method_capability("push/event"), None);
        assert_eq!(channel_method_capability("channels/invented"), None);
    }

    #[test]
    fn every_capability_path_is_a_conforming_identifier() {
        // §17.2 requires capability paths to match [A-Za-z0-9._:*-].
        for path in CAPABILITY_PATHS {
            assert!(
                crate::manifest::is_ascii_identifier(path),
                "{path} is not a conforming identifier"
            );
        }
    }

    #[test]
    fn derivation_fails_closed() {
        let decl = FeatureSetDeclaration {
            description: "Demo".into(),
            uses: vec!["channels.publish".into(), "channels.incoming".into()],
            rollback: false,
            tag_ontology: None,
        };
        let grant = CapabilityGrant::from_effective(["channels.publish"]);
        assert_eq!(
            derive_feature_set(&decl, &grant),
            FeatureSetStatus::Disabled(DisabledReason::MissingCapabilities {
                missing: vec!["channels.incoming".into()]
            })
        );
    }
}
