//! Event tags (SPEC §16 / RFC-001 rev 2).
//!
//! Tags describe; they never authorize (§16.6). Admission is decided by the
//! capability grant and channel authorization *before* any tag is read.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Reserved `chat:*` core vocabulary (SPEC §16.2).
///
/// Descriptions are inherited from §16.2 and MUST NOT be redescribed by producers.
pub mod chat {
    // Addressing
    pub const ADDRESSED: &str = "chat:addressed";
    pub const MENTION: &str = "chat:mention";
    pub const REPLY: &str = "chat:reply";
    pub const DM: &str = "chat:dm";
    pub const AMBIENT: &str = "chat:ambient";
    pub const BROADCAST: &str = "chat:broadcast";
    pub const TO_SELF: &str = "chat:to-self";
    // Sender
    pub const FROM_HUMAN: &str = "chat:from-human";
    pub const FROM_BOT: &str = "chat:from-bot";
    pub const FROM_SELF: &str = "chat:from-self";
    pub const FROM_AGENT: &str = "chat:from-agent";
    // Lifecycle (plain creation carries no tag)
    pub const EDITED: &str = "chat:edited";
    pub const DELETED: &str = "chat:deleted";
    pub const REACTION: &str = "chat:reaction";
    pub const REACTION_REMOVE: &str = "chat:reaction-remove";
    // Content
    pub const HAS_IMAGE: &str = "chat:has-image";
    pub const HAS_AUDIO: &str = "chat:has-audio";
    pub const HAS_FILE: &str = "chat:has-file";
    pub const HAS_LINK: &str = "chat:has-link";
    pub const COMMAND: &str = "chat:command";
    // Locus
    pub const PRIVATE: &str = "chat:private";
    pub const GROUP: &str = "chat:group";
    pub const THREAD: &str = "chat:thread";

    /// Every reserved `chat:*` tag.
    pub const ALL: &[&str] = &[
        ADDRESSED,
        MENTION,
        REPLY,
        DM,
        AMBIENT,
        BROADCAST,
        TO_SELF,
        FROM_HUMAN,
        FROM_BOT,
        FROM_SELF,
        FROM_AGENT,
        EDITED,
        DELETED,
        REACTION,
        REACTION_REMOVE,
        HAS_IMAGE,
        HAS_AUDIO,
        HAS_FILE,
        HAS_LINK,
        COMMAND,
        PRIVATE,
        GROUP,
        THREAD,
    ];
}

/// Namespaces reserved by the specification (§16.1).
pub const RESERVED_NAMESPACES: &[&str] = &["chat", "mcpl"];

/// Whether `tag` is namespaced at all. Producers MUST NOT emit bare tags (§16.1):
/// a bare `"mention"` is not a tag.
pub fn is_namespaced(tag: &str) -> bool {
    match tag.split_once(':') {
        Some((ns, rest)) => !ns.is_empty() && !rest.is_empty(),
        None => false,
    }
}

/// The namespace of a tag, if it has one.
pub fn namespace(tag: &str) -> Option<&str> {
    tag.split_once(':').map(|(ns, _)| ns)
}

/// Whether the tag sits in a namespace reserved by the specification.
pub fn is_reserved(tag: &str) -> bool {
    namespace(tag).is_some_and(|ns| RESERVED_NAMESPACES.contains(&ns))
}

/// Apply the **normative core closure** of SPEC §16.3.
///
/// ```text
/// chat:mention  ⇒ chat:addressed
/// chat:reply    ⇒ chat:addressed
/// chat:dm       ⇒ chat:addressed, chat:private
/// ```
///
/// Hosts MUST expand these, and MUST do so **without consulting any producer
/// ontology** — producer `implies` edges are advisory and require explicit
/// acceptance (§16.3, §16.5), so this function deliberately takes no ontology.
///
/// Expansion is transitive and purely additive. Because it is additive it can
/// produce both `chat:addressed` and `chat:ambient`; §16.3 resolves that by
/// **dropping `chat:ambient`**, which this function does after expansion.
pub fn expand_core_closure<I, S>(tags: I) -> BTreeSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out: BTreeSet<String> = tags.into_iter().map(|t| t.as_ref().to_string()).collect();

    // Transitive: iterate to a fixed point. The core graph is shallow, but writing
    // it as a fixed point keeps it correct if §16.3 grows an edge.
    loop {
        let mut added = false;
        let push = |set: &mut BTreeSet<String>, tag: &str, added: &mut bool| {
            if set.insert(tag.to_string()) {
                *added = true;
            }
        };
        if out.contains(chat::MENTION) || out.contains(chat::REPLY) || out.contains(chat::DM) {
            push(&mut out, chat::ADDRESSED, &mut added);
        }
        if out.contains(chat::DM) {
            push(&mut out, chat::PRIVATE, &mut added);
        }
        if !added {
            break;
        }
    }

    // §16.3 mutual exclusion: after expansion, `chat:addressed` wins over
    // `chat:ambient`. Carrying both makes a first-match-wins rule list depend on
    // rule ordering rather than on the event.
    if out.contains(chat::ADDRESSED) {
        out.remove(chat::AMBIENT);
    }

    out
}

// ── Producer ontology (§16.4 / RFC-001 §5) ────────────────────────────────────

/// An open-world hint catalog of the tags a feature set emits (SPEC §16.4).
///
/// It is a hint catalog, **not** a closed schema: it need not be exhaustive and
/// hosts MUST tolerate tags that are not described. Discovery is at `initialize`
/// only — there is no runtime ontology-query method, because a mutable ontology
/// cannot be meaningfully "accepted" (§16.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagOntology {
    /// Which reserved `chat:*` tags this server emits. Descriptions are inherited
    /// from §16.2 and are not repeated here.
    #[serde(rename = "coreTags", default, skip_serializing_if = "Option::is_none")]
    pub core_tags: Option<Vec<String>>,
    /// Producer-namespace tag descriptors, keyed by tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<BTreeMap<String, TagDescriptor>>,
    /// `key=value` families.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyed: Option<BTreeMap<String, KeyedTagFamily>>,
    /// Ordered suggested rules. **Advisory** — never applied automatically (§16.5).
    ///
    /// `defaultTreatment` is accepted as a deprecated alias (RFC-001 §5.1).
    #[serde(
        rename = "suggestedTreatment",
        alias = "defaultTreatment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub suggested_treatment: Option<Vec<TreatmentRule>>,
    /// `true` ⇒ the server may emit further tags in its namespaces beyond those
    /// described.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagDescriptor {
    /// Human/agent-readable description — the core of discoverability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facet: Option<TagFacet>,
    /// Subsumption edges. **Advisory** (§16.3): a host MUST NOT apply these
    /// automatically, and in particular MUST NOT apply an edge targeting a reserved
    /// `chat:*` tag unless the producer's ontology has been explicitly accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implies: Option<Vec<String>>,
    /// Per-tag suggested behaviour. **Advisory** (§16.5).
    #[serde(
        rename = "suggestedTreatment",
        alias = "defaultTreatment",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub suggested_treatment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stability: Option<TagStability>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TagFacet {
    Addressing,
    Sender,
    Content,
    Lifecycle,
    Locus,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TagStability {
    #[default]
    Stable,
    Experimental,
    Deprecated,
}

/// A `key=value` tag family. `values` is a **list** — its order is meaningful and
/// is preserved by the manifest digest (§17.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyedTagFamily {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub values: Option<Vec<String>>,
    /// Ordering is a hint **within this namespace only** — never a cross-server scale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ordered: Option<bool>,
}

/// One suggested-treatment rule. Matchers follow §16.7's recommended consumer shape.
///
/// `behavior` is left as a free string: the specification shows `immediate`, `mute`
/// and `throttle` in examples but defines no closed enum, and inventing one here
/// would reject conforming producers.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TreatmentRule {
    #[serde(rename = "tagsAny", default, skip_serializing_if = "Option::is_none")]
    pub tags_any: Option<Vec<String>>,
    #[serde(rename = "tagsAll", default, skip_serializing_if = "Option::is_none")]
    pub tags_all: Option<Vec<String>>,
    #[serde(rename = "tagsNone", default, skip_serializing_if = "Option::is_none")]
    pub tags_none: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_implies_addressed() {
        let out = expand_core_closure([chat::MENTION]);
        assert!(out.contains(chat::ADDRESSED));
        assert!(out.contains(chat::MENTION));
    }

    #[test]
    fn dm_implies_addressed_and_private() {
        let out = expand_core_closure([chat::DM]);
        assert!(out.contains(chat::ADDRESSED));
        assert!(out.contains(chat::PRIVATE));
    }

    #[test]
    fn ambient_is_dropped_when_addressed_survives_expansion() {
        let out = expand_core_closure([chat::AMBIENT, chat::REPLY]);
        assert!(out.contains(chat::ADDRESSED));
        assert!(!out.contains(chat::AMBIENT));
    }

    #[test]
    fn ambient_alone_survives() {
        let out = expand_core_closure([chat::AMBIENT, chat::FROM_BOT]);
        assert!(out.contains(chat::AMBIENT));
        assert!(!out.contains(chat::ADDRESSED));
    }

    #[test]
    fn producer_implies_edges_are_not_applied_by_the_core_closure() {
        // A producer declaring `discord:role-mention ⇒ chat:addressed` cannot
        // promote its own traffic: expansion never consults the ontology.
        let out = expand_core_closure(["discord:role-mention"]);
        assert!(!out.contains(chat::ADDRESSED));
    }

    #[test]
    fn bare_tags_are_not_namespaced() {
        assert!(!is_namespaced("mention"));
        assert!(is_namespaced("chat:mention"));
        assert!(is_namespaced("urgency:high"));
        assert!(is_reserved("chat:mention"));
        assert!(!is_reserved("discord:slash"));
    }

    #[test]
    fn ontology_accepts_the_deprecated_default_treatment_alias() {
        let onto: TagOntology = serde_json::from_str(
            r#"{"defaultTreatment":[{"tagsAny":["chat:addressed"],"behavior":"immediate"}]}"#,
        )
        .unwrap();
        assert_eq!(onto.suggested_treatment.as_ref().unwrap().len(), 1);
        // Round-trips under the current name.
        let out = serde_json::to_string(&onto).unwrap();
        assert!(out.contains("suggestedTreatment"));
    }
}
