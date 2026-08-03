//! Server manifest changes and the canonical content digest (SPEC §17 / RFC-003).
//!
//! The digest is the interop-critical surface: a Rust server and a TypeScript host
//! must derive byte-identical revisions from the same manifest.
//!
//! ```text
//! revision = "sha256:" + base64url_unpadded( SHA-256( JCS( manifest_without_revision ) ) )
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The complete `experimental.mcpl` object, as presented at `initialize`.
///
/// Kept as raw JSON deliberately: the digest covers *every* member, including
/// extension members this library does not model, so a typed round-trip that
/// dropped unknown fields would compute the wrong revision.
pub type Manifest = serde_json::Value;

/// Change domains (SPEC §17.1, App. B.4).
///
/// `version` and `revision` are not a domain: `version` is protocol identity, not
/// surface, and `revision` is derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ChangeDomain {
    /// Every member other than `version`, `revision` and `featureSets`.
    Capabilities,
    /// The `featureSets` member, excluding any `tagOntology` within it.
    FeatureSets,
    /// The `tagOntology` of any feature set.
    TagOntology,
}

/// `mcpl/manifestChanged` (Server → Host, Notification) — SPEC §17.3.
///
/// It carries **no payload**: no diff, no list of what changed, no policy
/// conclusion. A host that acts on it MUST fetch (§17.4) before changing anything,
/// and the host's diff of the fetched manifest is what is authoritative.
///
/// No capability path gates this notification (§17.3).
/// App. B.3 sets `additionalProperties: false` on these params, so unknown members
/// are refused rather than silently ignored — the notification carries no payload,
/// and a member that looks like one is a conformance defect worth surfacing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestChangedParams {
    /// Opaque. Hosts MUST NOT parse or order revisions; equality is the only
    /// defined operation.
    pub revision: String,
    pub domains: Vec<ChangeDomain>,
}

/// `mcpl/manifest` (Host → Server, Request) — SPEC §17.4. Takes no params.
///
/// The **result** is the `experimental.mcpl` object itself, in the same shape
/// `initialize` carries — not a re-wrapped one — so it deserializes as a
/// [`Manifest`] or as [`crate::capabilities::McplCapabilities`]. It is complete,
/// never a delta: a delta would require the host to trust the server's account of
/// its own previous state.
///
/// A server that does not implement it MUST return an error, not silence (§6.6).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestParams {}

/// Host-derived impact vocabulary for the change receipt (SPEC §17.6, App. B.4).
///
/// Closed and **host-derived** — never a server-authored flag such as
/// `requiresReview`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeImpact {
    CapabilityRevoked,
    CapabilityExpansionPending,
    FeatureDegraded,
    FeatureRestored,
    OntologyAcceptanceInvalidated,
    OntologyReferenceUndeclared,
    SurfaceChanged,
}

/// Disposition attached to each impact (SPEC §17.6, App. B.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    Applied,
    DecisionNeeded,
    Informational,
}

// ── Canonical digest (§17.2) ──────────────────────────────────────────────────

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum DigestError {
    #[error("manifest must be a JSON object")]
    NotAnObject,
    /// A string in an identifier position is empty or contains a character outside
    /// `[A-Za-z0-9._:*-]` (§17.2).
    ///
    /// Refusing to produce a revision is the fail-closed reading: the ASCII rule
    /// exists precisely because UTF-8 and UTF-16 ordering diverge above U+FFFF, and
    /// that divergence becomes reachable the moment non-ASCII enters a set-valued
    /// array. Note this is distinct from §6.4's `invalid_uses`, which disables one
    /// feature set while the manifest still gets a revision.
    #[error("{position} is not a conforming identifier: {value:?}")]
    IdentifierCharset { position: String, value: String },
    /// A JSON number outside the IEEE-754 double range RFC 8785 canonicalization is
    /// defined over. Unreachable through `serde_json`'s default configuration.
    #[error("number {0} has no IEEE-754 double representation")]
    NumberNotRepresentable(String),
}

impl DigestError {
    /// The stable error code used by the shared conformance vectors.
    pub fn code(&self) -> &'static str {
        match self {
            DigestError::NotAnObject => "manifest_not_object",
            DigestError::IdentifierCharset { .. } => "identifier_charset",
            DigestError::NumberNotRepresentable(_) => "number_not_representable",
        }
    }
}

/// Compute the canonical revision of a manifest (SPEC §17.2).
///
/// The `revision` member is removed before hashing so the digest never covers
/// itself. Nothing else is stripped — `version` is included.
///
/// The result is content-derived, so a cooperative server cannot accidentally
/// change its surface without announcing it. It is still **server-authored and
/// untrusted**: a host MUST NOT treat an unchanged revision as proof that nothing
/// changed (§17.1).
pub fn manifest_revision(manifest: &Manifest) -> Result<String, DigestError> {
    let canonical = canonical_manifest_json(manifest)?;
    let digest = Sha256::digest(canonical.as_bytes());
    Ok(format!("sha256:{}", base64url_unpadded(&digest)))
}

/// The exact canonical bytes hashed by [`manifest_revision`]: the manifest minus
/// `revision`, with set-like arrays normalized, serialized per RFC 8785.
///
/// Exposed because it is the half of the digest that is worth diffing when two
/// implementations disagree.
pub fn canonical_manifest_json(manifest: &Manifest) -> Result<String, DigestError> {
    let obj = manifest.as_object().ok_or(DigestError::NotAnObject)?;
    let mut stripped = serde_json::Value::Object(obj.clone());
    stripped
        .as_object_mut()
        .expect("just built from an object")
        // Stripped at the **root only**. §17.2 removes "the `revision` member" of
        // the manifest object, not everything named `revision`: a nested member of
        // that name is ordinary content and is hashed.
        .remove("revision");
    validate_identifiers(&stripped)?;
    normalize_sets(&mut stripped);
    let mut out = String::new();
    write_jcs(&stripped, &mut out)?;
    Ok(out)
}

/// Whether a string is a conforming capability path / tag identifier for digest
/// purposes: `[A-Za-z0-9._:*-]` (SPEC §17.2).
///
/// For ASCII strings UTF-8 byte order, UTF-16 code-unit order and code-point order
/// coincide, so the Rust/JavaScript sort divergence above U+FFFF cannot arise for
/// the values this actually applies to.
pub fn is_ascii_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'*' | b'-')
        })
}

// ── Identifier positions (§17.2) ──────────────────────────────────────────────
//
// §17.2 states that capability paths and tag identifiers MUST be ASCII, but does
// not enumerate where those occur. The positions below are the fail-closed reading
// agreed with the shared conformance vectors:
//
//   <root capability member names, recursively>   — §5.1: advertisement mirrors the
//                                                     capability paths, so every
//                                                     nested member name is a path
//                                                     segment. `version`,
//                                                     `revision` and `featureSets`
//                                                     are not capabilities.
//   featureSets.<name>
//   featureSets.*.uses[]
//   featureSets.*.tagOntology.coreTags[]
//   featureSets.*.tagOntology.tags.<tag>
//   featureSets.*.tagOntology.tags.*.implies[]
//   featureSets.*.tagOntology.tags.*.facet
//   featureSets.*.tagOntology.keyed.<key>
//   featureSets.*.tagOntology.keyed.*.values[]
//   featureSets.*.tagOntology.suggestedTreatment[].tags{Any,All,None}[]
//
// Free text — `description`, `desc` — is deliberately *not* an identifier position,
// and §5.4's "generic recursive walk" is why the capability side recurses rather
// than checking root names only.

fn validate_identifiers(manifest: &serde_json::Value) -> Result<(), DigestError> {
    let Some(obj) = manifest.as_object() else {
        return Ok(());
    };
    for (key, value) in obj {
        match key.as_str() {
            // Protocol identity and derived state, not capabilities.
            "version" | "revision" => {}
            "featureSets" => validate_feature_sets_identifiers(value)?,
            _ => {
                check_identifier(key, key)?;
                validate_capability_member_names(key, value)?;
            }
        }
    }
    Ok(())
}

fn validate_capability_member_names(
    path: &str,
    value: &serde_json::Value,
) -> Result<(), DigestError> {
    let Some(obj) = value.as_object() else {
        return Ok(());
    };
    for (key, child) in obj {
        let child_path = format!("{path}.{key}");
        check_identifier(&child_path, key)?;
        validate_capability_member_names(&child_path, child)?;
    }
    Ok(())
}

fn validate_feature_sets_identifiers(feature_sets: &serde_json::Value) -> Result<(), DigestError> {
    let Some(declared) = feature_sets.as_object() else {
        return Ok(());
    };
    for (name, decl) in declared {
        let base = format!("featureSets.{name}");
        check_identifier(&base, name)?;

        let Some(decl) = decl.as_object() else {
            continue;
        };
        check_string_array(&format!("{base}.uses"), decl.get("uses"))?;

        let Some(ontology) = decl.get("tagOntology").and_then(|v| v.as_object()) else {
            continue;
        };
        let onto_path = format!("{base}.tagOntology");
        check_string_array(&format!("{onto_path}.coreTags"), ontology.get("coreTags"))?;

        if let Some(tags) = ontology.get("tags").and_then(|v| v.as_object()) {
            for (tag, descriptor) in tags {
                let tag_path = format!("{onto_path}.tags.{tag}");
                check_identifier(&tag_path, tag)?;
                let Some(descriptor) = descriptor.as_object() else {
                    continue;
                };
                check_string_array(&format!("{tag_path}.implies"), descriptor.get("implies"))?;
                if let Some(facet) = descriptor.get("facet").and_then(|v| v.as_str()) {
                    check_identifier(&format!("{tag_path}.facet"), facet)?;
                }
            }
        }

        if let Some(keyed) = ontology.get("keyed").and_then(|v| v.as_object()) {
            for (key, family) in keyed {
                let key_path = format!("{onto_path}.keyed.{key}");
                check_identifier(&key_path, key)?;
                if let Some(family) = family.as_object() {
                    check_string_array(&format!("{key_path}.values"), family.get("values"))?;
                }
            }
        }

        if let Some(rules) = ontology
            .get("suggestedTreatment")
            .and_then(|v| v.as_array())
        {
            for (i, rule) in rules.iter().enumerate() {
                let Some(rule) = rule.as_object() else {
                    continue;
                };
                let rule_path = format!("{onto_path}.suggestedTreatment[{i}]");
                for matcher in ["tagsAny", "tagsAll", "tagsNone"] {
                    check_string_array(&format!("{rule_path}.{matcher}"), rule.get(matcher))?;
                }
            }
        }
    }
    Ok(())
}

/// Check every element of an array-valued identifier position.
///
/// The check applies only when the array is well-formed (all elements are
/// strings). An array carrying any non-string member is non-conforming input:
/// per §17.2's totality rule it is hashed **verbatim** — no set sort, no dedupe,
/// and no identifier check — and rejected later by validation, never by the
/// digest. The identifier refusal exists solely to keep the UTF-8/UTF-16 sort
/// divergence unreachable, and an unsorted array cannot diverge.
fn check_string_array(path: &str, value: Option<&serde_json::Value>) -> Result<(), DigestError> {
    let Some(items) = value.and_then(|v| v.as_array()) else {
        return Ok(());
    };
    if !items.iter().all(|item| item.is_string()) {
        return Ok(());
    }
    for item in items {
        if let Some(s) = item.as_str() {
            check_identifier(&format!("{path}[]"), s)?;
        }
    }
    Ok(())
}

fn check_identifier(position: &str, value: &str) -> Result<(), DigestError> {
    if is_ascii_identifier(value) {
        Ok(())
    } else {
        Err(DigestError::IdentifierCharset {
            position: position.to_string(),
            value: value.to_string(),
        })
    }
}

// ── Domain diff (§17.1) ───────────────────────────────────────────────────────

/// Which of §17.1's three domains differ between two manifests.
///
/// The partition is exactly §17.1's table:
///
/// | Domain | Members |
/// |---|---|
/// | `capabilities` | every member other than `version`, `revision` and `featureSets` |
/// | `featureSets` | the `featureSets` member, excluding any `tagOntology` within it |
/// | `tagOntology` | the `tagOntology` of any feature set |
///
/// `version` and `revision` are not a domain and never contribute.
///
/// Comparison is over the **canonicalized** subtrees, so a reordered `uses` or a
/// re-serialized object is not reported as a change. An **absent** member and an
/// **empty** one are *not* equated: they canonicalize differently, so they are
/// different manifests, and a member appearing or disappearing is a change to its
/// domain (§17.3) — `featureSets` appearing announces `featureSets` and brings the
/// `tagOntology` domain into existence with it.
///
/// This is a convenience for a *server* deriving the `domains` of an announcement.
/// It is **not** a host authorization input: §17.1 makes the host's own diff of the
/// fetched manifest authoritative for every decision, and a server's `domains` is a
/// hint the host may ignore entirely.
pub fn changed_domains(
    old: &Manifest,
    new: &Manifest,
) -> Result<std::collections::BTreeSet<ChangeDomain>, DigestError> {
    let mut out = std::collections::BTreeSet::new();

    let old = canonical_parts(old)?;
    let new = canonical_parts(new)?;

    if old.capabilities != new.capabilities {
        out.insert(ChangeDomain::Capabilities);
    }
    if old.feature_sets != new.feature_sets {
        out.insert(ChangeDomain::FeatureSets);
    }
    if old.tag_ontologies != new.tag_ontologies {
        out.insert(ChangeDomain::TagOntology);
    }
    Ok(out)
}

struct CanonicalParts {
    /// Every member other than `version`, `revision`, `featureSets`.
    capabilities: String,
    /// `featureSets` with every `tagOntology` removed. `None` when the manifest
    /// has no `featureSets` member at all: absent and empty canonicalize
    /// differently (§17.2), so they are different manifests — the member appearing
    /// or disappearing IS a `featureSets` change (§17.3).
    feature_sets: Option<String>,
    /// Feature-set name → its `tagOntology`, for the sets that declare one.
    /// `None` when `featureSets` is absent: the member appearing brings the
    /// ontology domain into existence with it, so absent → present announces
    /// `tagOntology` as well.
    tag_ontologies: Option<std::collections::BTreeMap<String, String>>,
}

fn canonical_parts(manifest: &Manifest) -> Result<CanonicalParts, DigestError> {
    let obj = manifest.as_object().ok_or(DigestError::NotAnObject)?;
    let mut normalized = serde_json::Value::Object(obj.clone());
    normalize_sets(&mut normalized);
    let normalized = normalized
        .as_object()
        .expect("still an object")
        .clone();

    let mut capabilities = serde_json::Map::new();
    for (key, value) in &normalized {
        if !matches!(key.as_str(), "version" | "revision" | "featureSets") {
            capabilities.insert(key.clone(), value.clone());
        }
    }

    let (feature_sets, tag_ontologies) = match normalized.get("featureSets") {
        Some(serde_json::Value::Object(declared)) => {
            let mut tag_ontologies = std::collections::BTreeMap::new();
            let mut feature_sets = serde_json::Map::new();
            for (name, decl) in declared {
                let mut stripped = decl.clone();
                if let Some(decl_obj) = stripped.as_object_mut() {
                    if let Some(ontology) = decl_obj.remove("tagOntology") {
                        let mut rendered = String::new();
                        write_jcs(&ontology, &mut rendered)?;
                        tag_ontologies.insert(name.clone(), rendered);
                    }
                }
                feature_sets.insert(name.clone(), stripped);
            }
            let mut rendered = String::new();
            write_jcs(&serde_json::Value::Object(feature_sets), &mut rendered)?;
            (Some(rendered), Some(tag_ontologies))
        }
        // Not the map shape §5.1/§6.1 defines. Rather than guess where the
        // `tagOntology` members are, report any difference as a `featureSets`
        // change: over-reporting a domain costs a re-fetch, under-reporting hides
        // a narrowing.
        Some(other) => {
            let mut rendered = String::new();
            write_jcs(other, &mut rendered)?;
            (Some(rendered), Some(std::collections::BTreeMap::new()))
        }
        // Absent is not projected to `{}`: the two canonicalize differently, so
        // `{"version":"0.5"}` → `{"version":"0.5","featureSets":{}}` is a change.
        None => (None, None),
    };

    let mut capabilities_json = String::new();
    write_jcs(&serde_json::Value::Object(capabilities), &mut capabilities_json)?;

    Ok(CanonicalParts {
        capabilities: capabilities_json,
        feature_sets,
        tag_ontologies,
    })
}

// ── Set normalization (§17.2) ─────────────────────────────────────────────────
//
// Set-like: `uses`, `coreTags`, `tagOntology.tags.*.implies`.
// List-like: `keyed.*.values`, and every array not named above.
//
// Normalization is applied **by structural path** rather than by field name at any
// depth, so an unrelated extension array that happens to be called `uses` keeps its
// order (§17.2: "any array not listed is a list; its order is part of the manifest").

fn normalize_sets(manifest: &mut serde_json::Value) {
    let Some(feature_sets) = manifest.get_mut("featureSets") else {
        return;
    };
    // §17.2's set paths are written against the object form's `featureSets.*.uses`
    // (SPEC §5.1/§6.1/§8.1, RFC-003). Any other shape — including RFC-001's
    // array-of-declarations example, which was a documented cross-doc error
    // (corrected 2026-08-02) — is non-conforming and is hashed **verbatim**: no
    // set normalization and no identifier check applies inside it. Validation is
    // where the shape fails; the digest's job is to give two implementations the
    // same answer for the same bytes.
    let Some(map) = feature_sets.as_object_mut() else {
        return;
    };
    for (_, decl) in map.iter_mut() {
        normalize_feature_set(decl);
    }
}

fn normalize_feature_set(decl: &mut serde_json::Value) {
    let Some(obj) = decl.as_object_mut() else {
        return;
    };
    sort_set_field(obj, "uses");

    let Some(ontology) = obj.get_mut("tagOntology").and_then(|v| v.as_object_mut()) else {
        return;
    };
    sort_set_field(ontology, "coreTags");

    if let Some(tags) = ontology.get_mut("tags").and_then(|v| v.as_object_mut()) {
        for (_, descriptor) in tags.iter_mut() {
            if let Some(descriptor) = descriptor.as_object_mut() {
                sort_set_field(descriptor, "implies");
            }
        }
    }
}

/// Sort one set-valued field of `obj` in place: UTF-8 byte order ascending,
/// duplicates removed (§17.2 / RFC-003 §3.1).
///
/// The digest is **total**: set semantics apply only when the value actually *is*
/// an array **and every element is a string**. A wrong-typed value in a set
/// position (`"uses": "tools"`), or a set-declared array carrying any non-string
/// member (`"uses": [1]`), is left untouched and hashed verbatim — no sort, no
/// dedupe. Validation (§6.4 `invalid_uses`) is where non-conforming input fails,
/// not the digest.
///
/// Public so the shared conformance sort vectors exercise this exact comparator
/// rather than a test-local reimplementation of it.
pub fn sort_set_field(obj: &mut serde_json::Map<String, serde_json::Value>, field: &str) {
    let Some(value) = obj.get_mut(field) else {
        return;
    };
    let Some(array) = value.as_array() else {
        return;
    };

    let mut items: Vec<&str> = Vec::with_capacity(array.len());
    for element in array {
        let Some(s) = element.as_str() else {
            // Non-conforming set member: hash the array verbatim (§17.2 totality).
            return;
        };
        items.push(s);
    }
    // Sort by UTF-8 byte sequence ascending. Rust's `str: Ord` is exactly that.
    items.sort_unstable();
    items.dedup();

    *value = serde_json::Value::Array(
        items
            .into_iter()
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect(),
    );
}

// ── RFC 8785 (JCS) ────────────────────────────────────────────────────────────

fn write_jcs(value: &serde_json::Value, out: &mut String) -> Result<(), DigestError> {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(n) => out.push_str(&jcs_number(n)?),
        serde_json::Value::String(s) => write_jcs_string(s, out),
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs(item, out)?;
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            // RFC 8785 §3.2.3: members are sorted by the UTF-16 code units of their
            // names. serde_json's default map is sorted by UTF-8 bytes, which differs
            // above U+FFFF, so re-sort explicitly rather than relying on iteration order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_jcs_string(key, out);
                out.push(':');
                write_jcs(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// RFC 8785 §3.2.2.3 defers number serialization to ECMAScript `Number::toString`.
///
/// **Every number goes through `f64` first.** That is not a shortcut: JavaScript has
/// no other numeric type, so a JSON integer above 2^53 is already the nearest double
/// by the time a JS peer has parsed it. Rounding here is what makes the two
/// implementations agree; printing an `i64` exactly would be the divergence.
/// (RFC 8785 is defined over the I-JSON double range for the same reason.)
fn jcs_number(n: &serde_json::Number) -> Result<String, DigestError> {
    let f = n
        .as_f64()
        .ok_or_else(|| DigestError::NumberNotRepresentable(n.to_string()))?;
    Ok(ecmascript_number(f))
}

/// ECMAScript `Number::toString` (ECMA-262 §6.1.6.1.20), radix 10.
///
/// Rust's own `Display` is *not* this: it never uses exponential notation, so
/// `1e21` prints as 22 digits and `5e-324` as 1078 characters — neither of which a
/// JavaScript peer would produce. The shortest round-tripping digit string is
/// obtained from `{:e}` (which is shortest-repr) and then re-laid-out under
/// ECMAScript's positional/exponential thresholds.
pub fn ecmascript_number(value: f64) -> String {
    // ECMAScript renders both +0 and -0 as "0".
    if value == 0.0 {
        return "0".to_string();
    }
    if value < 0.0 {
        return format!("-{}", ecmascript_number(-value));
    }

    // `{:e}` yields `d[.ddd]e<exp>` with the shortest round-tripping digits, i.e.
    // value == 0.<digits> × 10^(exp+1).
    let sci = format!("{value:e}");
    let (mantissa, exponent) = sci
        .split_once('e')
        .expect("`{:e}` always emits an exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i32 = exponent
        .parse()
        .expect("`{:e}` always emits a decimal exponent");

    // ECMAScript's n, k, s: value == s × 10^(n-k), with k digits in s.
    let s = digits.as_str();
    let k = s.len() as i32;
    let n = exponent + 1;

    if k <= n && n <= 21 {
        // Integer with trailing zeros: "100000000000000000000".
        let mut out = String::from(s);
        out.extend(std::iter::repeat_n('0', (n - k) as usize));
        out
    } else if 0 < n && n <= 21 {
        // Decimal point inside the digits: "2.5".
        format!("{}.{}", &s[..n as usize], &s[n as usize..])
    } else if -6 < n && n <= 0 {
        // Leading zeros: "0.000001".
        let mut out = String::from("0.");
        out.extend(std::iter::repeat_n('0', (-n) as usize));
        out.push_str(s);
        out
    } else {
        // Exponential: "1e+21", "1e-7", "1.7976931348623157e+308".
        let e = n - 1;
        let sign = if e >= 0 { '+' } else { '-' };
        if k == 1 {
            format!("{s}e{sign}{}", e.abs())
        } else {
            format!("{}.{}e{sign}{}", &s[..1], &s[1..], e.abs())
        }
    }
}

/// RFC 8785 §3.2.2.2: JSON string serialization as ECMAScript `JSON.stringify`
/// produces it — the six shorthand escapes, `\u00xx` (lowercase hex) for the
/// remaining control characters, and every other code point emitted literally.
fn write_jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// RFC 4648 §5 base64url without `=` padding.
fn base64url_unpadded(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[(triple >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(triple >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6 & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn spec_1722_test_vector() {
        let manifest = json!({
            "version": "0.5",
            "pushEvents": true,
            "contextHooks": { "beforeInference": true },
            "inferenceLifecycle": true,
            "channels": { "register": true, "publish": true, "incoming": true },
            "featureSets": {
                "demo.messaging": {
                    "description": "Demo",
                    "uses": ["channels.publish", "channels.incoming", "pushEvents", "tools"]
                }
            }
        });

        assert_eq!(
            canonical_manifest_json(&manifest).unwrap(),
            r#"{"channels":{"incoming":true,"publish":true,"register":true},"contextHooks":{"beforeInference":true},"featureSets":{"demo.messaging":{"description":"Demo","uses":["channels.incoming","channels.publish","pushEvents","tools"]}},"inferenceLifecycle":true,"pushEvents":true,"version":"0.5"}"#
        );
        assert_eq!(
            manifest_revision(&manifest).unwrap(),
            "sha256:_YZTS0h1tqTAMZI6eElCszSQE2WNx3xhAhmgUvNI9H4"
        );
    }

    #[test]
    fn revision_never_covers_itself() {
        let without = json!({ "version": "0.5", "pushEvents": true });
        let expected = manifest_revision(&without).unwrap();

        let mut with = without.clone();
        with["revision"] = json!("sha256:some-other-value-entirely-aaaaaaaaaaaaaaa");
        assert_eq!(manifest_revision(&with).unwrap(), expected);
    }

    #[test]
    fn revision_matches_the_appendix_b3_pattern() {
        let rev = manifest_revision(&json!({ "version": "0.5" })).unwrap();
        let body = rev.strip_prefix("sha256:").expect("sha256: prefix");
        assert_eq!(body.len(), 43);
        assert!(body.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn uses_is_a_set_and_input_order_does_not_matter() {
        let a = json!({ "version": "0.5", "featureSets": { "f": { "description": "d",
            "uses": ["tools", "pushEvents"] } } });
        let b = json!({ "version": "0.5", "featureSets": { "f": { "description": "d",
            "uses": ["pushEvents", "tools", "pushEvents"] } } });
        assert_eq!(manifest_revision(&a).unwrap(), manifest_revision(&b).unwrap());
    }

    #[test]
    fn keyed_values_is_a_list_and_order_is_preserved() {
        let a = json!({ "version": "0.5", "featureSets": { "f": { "description": "d",
            "uses": ["tools"],
            "tagOntology": { "keyed": { "urgency": { "values": ["low", "normal", "high"] } } } } } });
        let b = json!({ "version": "0.5", "featureSets": { "f": { "description": "d",
            "uses": ["tools"],
            "tagOntology": { "keyed": { "urgency": { "values": ["high", "low", "normal"] } } } } } });
        assert_ne!(manifest_revision(&a).unwrap(), manifest_revision(&b).unwrap());
        assert!(canonical_manifest_json(&a)
            .unwrap()
            .contains(r#""values":["low","normal","high"]"#));
    }

    #[test]
    fn core_tags_and_implies_are_sets() {
        let canonical = canonical_manifest_json(&json!({
            "version": "0.5",
            "featureSets": { "f": { "description": "d", "uses": ["tools"], "tagOntology": {
                "coreTags": ["chat:mention", "chat:addressed"],
                "tags": { "x:y": { "implies": ["chat:broadcast", "chat:ambient"] } }
            } } }
        }))
        .unwrap();
        assert!(canonical.contains(r#""coreTags":["chat:addressed","chat:mention"]"#));
        assert!(canonical.contains(r#""implies":["chat:ambient","chat:broadcast"]"#));
    }

    #[test]
    fn unrelated_arrays_keep_their_order() {
        let canonical = canonical_manifest_json(&json!({
            "version": "0.5",
            "somethingElse": ["z", "a"]
        }))
        .unwrap();
        assert!(canonical.contains(r#""somethingElse":["z","a"]"#));
    }

    #[test]
    fn wrong_typed_set_fields_hash_verbatim() {
        // The digest is total: set semantics apply only when the value actually is
        // an array. A wrong-typed `uses` is hashed verbatim; §6.4's `invalid_uses`
        // validation is where it fails, not the digest.
        let canonical = canonical_manifest_json(&json!({
            "version": "0.5",
            "featureSets": { "f": { "description": "d", "uses": "tools" } }
        }))
        .unwrap();
        assert!(canonical.contains(r#""uses":"tools""#), "{canonical}");

        // Second totality corollary: a set-DECLARED array carrying any non-string
        // member is likewise hashed verbatim — no sort, no dedupe, no identifier
        // check. Order and the duplicate are preserved; the digest never refuses.
        let canonical = canonical_manifest_json(&json!({
            "version": "0.5",
            "featureSets": { "f": { "description": "d", "uses": ["tools", 7, "pushEvents", "tools"] } }
        }))
        .unwrap();
        assert!(
            canonical.contains(r#""uses":["tools",7,"pushEvents","tools"]"#),
            "{canonical}"
        );
    }

    #[test]
    fn array_form_feature_sets_hash_verbatim() {
        // RFC-001's array-of-declarations example was a documented cross-doc error
        // (corrected 2026-08-02). The non-conforming shape is hashed verbatim: no
        // set normalization inside it — `uses` keeps its input order — and no
        // identifier check applies in it.
        let canonical = canonical_manifest_json(&json!({
            "version": "0.5",
            "featureSets": [
                { "name": "f", "description": "d", "uses": ["tools", "pushEvents"] }
            ]
        }))
        .unwrap();
        assert!(canonical.contains(r#""uses":["tools","pushEvents"]"#), "{canonical}");
    }

    #[test]
    fn numbers_follow_ecmascript_number_to_string() {
        // The thresholds RFC 8785 inherits from ECMAScript. Rust's `Display` gets
        // the last four of these wrong.
        for (input, expected) in [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-17.0, "-17"),
            (2.5, "2.5"),
            (0.1, "0.1"),
            (0.333_333_333_333_333_3, "0.3333333333333333"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (9_007_199_254_740_991.0, "9007199254740991"),
            (9_007_199_254_740_992.0, "9007199254740992"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
        ] {
            assert_eq!(ecmascript_number(input), expected, "for {input:?}");
        }
    }

    #[test]
    fn integers_are_rounded_to_double_like_javascript() {
        // A JS peer parses this as 9007199254740992 before it can hash anything,
        // so printing the i64 exactly would be the interop bug, not the fix.
        let canonical =
            canonical_manifest_json(&json!({ "version": "0.5", "x": 9007199254740993i64 })).unwrap();
        assert!(canonical.contains(r#""x":9007199254740992"#), "{canonical}");
    }

    #[test]
    fn identifier_charset_is_enforced_and_fails_closed() {
        // Nested capability member name — §5.4's generic recursive walk means a
        // root-only check is not enough.
        let err = manifest_revision(&json!({
            "version": "0.5",
            "contextHooks": { "beforeInference": { "inject": { "before user": true } } }
        }))
        .unwrap_err();
        assert_eq!(err.code(), "identifier_charset");

        // Feature-set name, `uses` entry, and a tag key.
        for manifest in [
            json!({ "version": "0.5", "featureSets": { "demo/messaging": {
                "description": "d", "uses": ["tools"] } } }),
            json!({ "version": "0.5", "featureSets": { "demo.m": {
                "description": "d", "uses": ["channels.publish "] } } }),
            json!({ "version": "0.5", "featureSets": { "demo.m": {
                "description": "d", "uses": [""] } } }),
            json!({ "version": "0.5", "featureSets": { "demo.m": {
                "description": "d", "uses": ["tools"],
                "tagOntology": { "tags": { "demo:naïve": { "desc": "x" } } } } } }),
        ] {
            assert_eq!(
                manifest_revision(&manifest).unwrap_err().code(),
                "identifier_charset",
                "accepted {manifest}"
            );
        }
    }

    #[test]
    fn free_text_is_not_an_identifier_position() {
        // `description` and `desc` are prose; only identifiers are charset-bound.
        assert!(manifest_revision(&json!({
            "version": "0.5",
            "featureSets": { "demo.m": {
                "description": "Café 日本語 🙂",
                "uses": ["tools"],
                "tagOntology": { "tags": { "demo:accent": { "desc": "naïve résumé" } } }
            } }
        }))
        .is_ok());
    }

    #[test]
    fn boolean_shorthand_is_not_expanded_by_the_digest() {
        // §5.1's shorthand is an input to the grant computation, not a
        // canonicalization step: expanding it would make the digest depend on a
        // vocabulary §5.4 says will grow.
        let shorthand = json!({ "version": "0.5", "channels": true });
        let expanded = json!({ "version": "0.5", "channels": {
            "register": true, "lifecycle": true, "publish": true, "incoming": true,
            "streaming": true, "acknowledge": true, "typing": true } });
        assert_ne!(
            manifest_revision(&shorthand).unwrap(),
            manifest_revision(&expanded).unwrap()
        );
    }

    #[test]
    fn revision_is_stripped_at_the_root_only() {
        let canonical = canonical_manifest_json(&json!({
            "version": "0.5",
            "revision": "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "demoExtension": { "revision": "not-stripped" }
        }))
        .unwrap();
        assert_eq!(
            canonical,
            r#"{"demoExtension":{"revision":"not-stripped"},"version":"0.5"}"#
        );
    }

    #[test]
    fn false_and_null_members_are_content_not_absence() {
        let present = json!({ "version": "0.5", "pushEvents": false, "modelInfo": null,
            "inferenceLifecycle": true });
        let absent = json!({ "version": "0.5", "inferenceLifecycle": true });
        assert_ne!(
            manifest_revision(&present).unwrap(),
            manifest_revision(&absent).unwrap()
        );
    }

    #[test]
    fn the_digest_function_is_total_over_objects() {
        // A host recomputes the digest of whatever it fetched *before* deciding
        // anything about it (§6.6: rejection is diagnostics, not authorization), so
        // an invalid-but-parseable manifest must still produce a value.
        assert_eq!(canonical_manifest_json(&json!({})).unwrap(), "{}");
        assert_eq!(manifest_revision(&json!([])).unwrap_err().code(), "manifest_not_object");
    }

    #[test]
    fn domains_partition_the_manifest() {
        let base = json!({
            "version": "0.5",
            "pushEvents": true,
            "featureSets": { "demo.m": { "description": "d", "uses": ["pushEvents"],
                "tagOntology": { "coreTags": ["chat:mention"] } } }
        });

        // Reordering a set and restating the revision changes nothing.
        let mut same = base.clone();
        same["revision"] = json!("sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        same["featureSets"]["demo.m"]["uses"] = json!(["pushEvents", "pushEvents"]);
        assert!(changed_domains(&base, &same).unwrap().is_empty());

        let mut caps = base.clone();
        caps["modelInfo"] = json!(true);
        assert_eq!(
            changed_domains(&base, &caps).unwrap(),
            [ChangeDomain::Capabilities].into_iter().collect()
        );

        // A `uses` change is featureSets, not tagOntology.
        let mut uses = base.clone();
        uses["featureSets"]["demo.m"]["uses"] = json!(["tools"]);
        assert_eq!(
            changed_domains(&base, &uses).unwrap(),
            [ChangeDomain::FeatureSets].into_iter().collect()
        );

        // An ontology change is tagOntology, not featureSets.
        let mut onto = base.clone();
        onto["featureSets"]["demo.m"]["tagOntology"]["coreTags"] = json!(["chat:dm"]);
        assert_eq!(
            changed_domains(&base, &onto).unwrap(),
            [ChangeDomain::TagOntology].into_iter().collect()
        );

        // `version` is protocol identity, not surface, and is not a domain.
        let mut version = base.clone();
        version["version"] = json!("0.6");
        assert!(changed_domains(&base, &version).unwrap().is_empty());
    }

    #[test]
    fn absent_and_empty_feature_sets_are_different_manifests() {
        // §17.3: absent and empty canonicalize differently, so a member appearing
        // IS a change to its domain — and `featureSets` appearing brings the
        // `tagOntology` domain into existence with it.
        let without = json!({ "version": "0.5" });
        let with_empty = json!({ "version": "0.5", "featureSets": {} });

        assert_ne!(
            manifest_revision(&without).unwrap(),
            manifest_revision(&with_empty).unwrap()
        );
        assert_eq!(
            changed_domains(&without, &with_empty).unwrap(),
            [ChangeDomain::FeatureSets, ChangeDomain::TagOntology]
                .into_iter()
                .collect()
        );
        // And symmetrically for the member disappearing.
        assert_eq!(
            changed_domains(&with_empty, &without).unwrap(),
            [ChangeDomain::FeatureSets, ChangeDomain::TagOntology]
                .into_iter()
                .collect()
        );
        assert!(changed_domains(&with_empty, &with_empty).unwrap().is_empty());
    }

    #[test]
    fn manifest_changed_params_reject_a_payload() {
        // App. B.3: `additionalProperties: false` — the notification carries no diff.
        let ok: ManifestChangedParams = serde_json::from_value(json!({
            "revision": "sha256:_YZTS0h1tqTAMZI6eElCszSQE2WNx3xhAhmgUvNI9H4",
            "domains": ["capabilities", "featureSets"]
        }))
        .unwrap();
        assert_eq!(ok.domains.len(), 2);

        assert!(serde_json::from_value::<ManifestChangedParams>(json!({
            "revision": "sha256:_YZTS0h1tqTAMZI6eElCszSQE2WNx3xhAhmgUvNI9H4",
            "domains": ["capabilities"],
            "removedCapabilities": ["channels.publish"]
        }))
        .is_err());

        assert!(serde_json::from_value::<ChangeDomain>(json!("everything")).is_err());
    }

    #[test]
    fn jcs_string_escaping() {
        let mut out = String::new();
        write_jcs_string("a\"b\\c\nd\u{0001}e\u{20AC}", &mut out);
        assert_eq!(out, "\"a\\\"b\\\\c\\nd\\u0001e\u{20AC}\"");
    }

    #[test]
    fn base64url_is_unpadded_and_url_safe() {
        assert_eq!(base64url_unpadded(&[]), "");
        assert_eq!(base64url_unpadded(b"f"), "Zg");
        assert_eq!(base64url_unpadded(b"fo"), "Zm8");
        assert_eq!(base64url_unpadded(b"foo"), "Zm9v");
        assert_eq!(base64url_unpadded(&[0xFB, 0xFF]), "-_8");
    }

    #[test]
    fn ascii_identifier_rule() {
        assert!(is_ascii_identifier("contextHooks.beforeInference.inject.system"));
        assert!(is_ascii_identifier("chat:reaction-remove"));
        assert!(is_ascii_identifier("channels.*"));
        assert!(!is_ascii_identifier("chat:mención"));
        assert!(!is_ascii_identifier(""));
    }
}
