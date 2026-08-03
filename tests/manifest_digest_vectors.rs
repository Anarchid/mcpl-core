//! Shared conformance vectors for the canonical manifest digest
//! (SPEC §17.2 / RFC-003 §3.1).
//!
//! These vectors were computed and verified by the `mcpl-core-ts` side so that the
//! two implementations agree byte for byte. **They are authoritative.** Where a
//! vector and this library's reading of the RFC disagree, the vector wins and the
//! disagreement is recorded in the PR — a silent deviation here is exactly the
//! failure the file exists to prevent.
//!
//! The checked-in copy lives at `tests/vectors/manifest-digest-vectors.json`. Point
//! `MCPL_DIGEST_VECTORS` at another path to run a newer or upstream copy without
//! rebuilding:
//!
//! ```sh
//! MCPL_DIGEST_VECTORS=../mcpl/conformance/manifest-digest-vectors.json cargo test
//! ```

use std::collections::BTreeMap;

use mcpl_core::manifest::{
    canonical_manifest_json, manifest_revision, sort_set_field, DigestError,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn load() -> Value {
    let path = std::env::var("MCPL_DIGEST_VECTORS").unwrap_or_else(|_| {
        format!(
            "{}/tests/vectors/manifest-digest-vectors.json",
            env!("CARGO_MANIFEST_DIR")
        )
    });
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read conformance vectors at {path}: {e}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("conformance vectors at {path} are not valid JSON: {e}"))
}

/// Accepts either the full vector document or a bare array of vectors.
fn vectors(doc: &Value, key: &str) -> Vec<Value> {
    match doc {
        Value::Array(items) => items.clone(),
        Value::Object(obj) => obj
            .get(key)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default(),
        _ => panic!("conformance vector document must be an object or an array"),
    }
}

fn name(vector: &Value) -> String {
    vector
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("<unnamed>")
        .to_string()
}

#[test]
fn every_manifest_vector_matches() {
    let doc = load();
    let vectors = vectors(&doc, "vectors");
    assert!(
        !vectors.is_empty(),
        "the conformance vector file carries no manifest vectors"
    );

    // Digests are collected so `sameDigestAs` / `differentDigestFrom` can be
    // checked after every vector has been evaluated, regardless of file order.
    let mut digests: BTreeMap<String, String> = BTreeMap::new();

    for vector in &vectors {
        let name = name(vector);
        let input = vector
            .get("input")
            .unwrap_or_else(|| panic!("vector {name} has no `input`"));

        if let Some(expected_code) = vector.get("expectError").and_then(|v| v.as_str()) {
            match manifest_revision(input) {
                Ok(revision) => panic!(
                    "vector {name}: expected error {expected_code}, got revision {revision}. \
                     Detail: {}",
                    vector
                        .get("errorDetail")
                        .and_then(|v| v.as_str())
                        .unwrap_or("(none given)")
                ),
                Err(err) => {
                    assert_eq!(err.code(), expected_code, "vector {name}: wrong error code")
                }
            }
            continue;
        }

        let canonical = manifest_revision(input)
            .and_then(|rev| canonical_manifest_json(input).map(|c| (rev, c)));
        let (revision, canonical) = canonical
            .unwrap_or_else(|e: DigestError| panic!("vector {name}: unexpected error {e}"));

        if let Some(expected) = vector.get("canonicalJson").and_then(|v| v.as_str()) {
            assert_eq!(canonical, expected, "vector {name}: canonical JCS bytes differ");
        }
        if let Some(expected) = vector.get("sha256Hex").and_then(|v| v.as_str()) {
            let hex = Sha256::digest(canonical.as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(hex, expected, "vector {name}: SHA-256 of the canonical bytes differs");
        }
        if let Some(expected) = vector.get("digest").and_then(|v| v.as_str()) {
            assert_eq!(revision, expected, "vector {name}: revision differs");
        }

        digests.insert(name, revision);
    }

    for vector in &vectors {
        let name = name(vector);
        let Some(mine) = digests.get(&name) else {
            continue;
        };
        if let Some(other) = vector.get("sameDigestAs").and_then(|v| v.as_str()) {
            let theirs = digests
                .get(other)
                .unwrap_or_else(|| panic!("vector {name} references unknown vector {other}"));
            assert_eq!(mine, theirs, "vector {name} must equal {other}");
        }
        if let Some(other) = vector.get("differentDigestFrom").and_then(|v| v.as_str()) {
            let theirs = digests
                .get(other)
                .unwrap_or_else(|| panic!("vector {name} references unknown vector {other}"));
            assert_ne!(mine, theirs, "vector {name} must differ from {other}");
        }
    }
}

#[test]
fn every_set_sort_vector_matches() {
    let doc = load();
    let vectors = vectors(&doc, "sortVectors");
    if vectors.is_empty() {
        // Older vector files carry manifest vectors only.
        return;
    }

    for vector in &vectors {
        let name = name(vector);
        let input = vector
            .get("input")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("sort vector {name} has no `input` array"))
            .clone();
        let expected: Vec<&str> = vector
            .get("sorted")
            .and_then(|v| v.as_array())
            .unwrap_or_else(|| panic!("sort vector {name} has no `sorted` array"))
            .iter()
            .map(|v| v.as_str().expect("sort vector outputs are strings"))
            .collect();

        // Run the vector through the *library's* set comparator — the one the
        // digest itself uses (§17.2: UTF-8 byte sequence, ascending, deduped) —
        // not a test-local re-sort, which would pass without exercising any
        // library code.
        let mut obj = serde_json::Map::new();
        obj.insert("uses".to_string(), Value::Array(input));
        sort_set_field(&mut obj, "uses");
        let actual: Vec<&str> = obj["uses"]
            .as_array()
            .expect("sort_set_field keeps the field an array")
            .iter()
            .map(|v| v.as_str().expect("sort vector inputs are strings"))
            .collect();

        assert_eq!(actual, expected, "sort vector {name}");
    }
}
