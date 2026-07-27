//! Round-trip sign/verify tests for every signed wire type (Envelope,
//! Index, Manifest, delegation Link), plus delegation chain verification
//! per core §2.5's numbered rules and rotation-chain verification per core
//! §1.1 rule 2 — table-driven per CLAUDE.md's Phase 1 gate ("table-driven
//! tests per rule").

use awp::delegation::{self, Link, Scope};
use awp::envelope::Envelope;
use awp::identity::{self, generate_keypair, Entity, Index, Key, Transport};
use awp::manifest::{Auth, Distribution, Hosted, IoSchema, Manifest};
use serde_json::json;
use std::time::{Duration, SystemTime};

fn fresh_key() -> ed25519_dalek::SigningKey {
    generate_keypair()
}

#[test]
fn envelope_round_trips_sign_and_verify() {
    let signing_key = fresh_key();
    let mut e = Envelope {
        awp: "0.1".to_string(),
        id: awp::envelope::new_id(),
        kind: "message".to_string(),
        from: "sender.example.com".to_string(),
        to: "recipient.example.com#agent".to_string(),
        thread: awp::envelope::new_id(),
        in_reply_to: None,
        ts: identity::now_rfc3339_milli(),
        ttl: 3600,
        session: None,
        delegation: None,
        body: json!({"text": "hi"}),
        sig: None,
    };
    e.sign(&signing_key, "k1").expect("sign");
    e.verify(&signing_key.verifying_key()).expect("verify");
}

#[test]
fn envelope_verify_fails_with_wrong_key() {
    let signing_key = fresh_key();
    let other_key = fresh_key();
    let mut e = Envelope {
        awp: "0.1".to_string(),
        id: awp::envelope::new_id(),
        kind: "message".to_string(),
        from: "sender.example.com".to_string(),
        to: "recipient.example.com".to_string(),
        thread: awp::envelope::new_id(),
        in_reply_to: None,
        ts: identity::now_rfc3339_milli(),
        ttl: 3600,
        session: None,
        delegation: None,
        body: json!({}),
        sig: None,
    };
    e.sign(&signing_key, "k1").unwrap();
    assert!(e.verify(&other_key.verifying_key()).is_err());
}

#[test]
fn envelope_null_fields_serialize_as_json_null_not_omitted() {
    let e = Envelope {
        awp: "0.1".to_string(),
        id: "01arz3ndektsv4rrffq69g5fav".to_string(),
        kind: "message".to_string(),
        from: "a.example.com".to_string(),
        to: "b.example.com".to_string(),
        thread: "01arz3ndektsv4rrffq69g5fav".to_string(),
        in_reply_to: None,
        ts: "2026-07-21T08:54:13.000Z".to_string(),
        ttl: 3600,
        session: None,
        delegation: None,
        body: json!({}),
        sig: None,
    };
    let v = serde_json::to_value(&e).unwrap();
    let obj = v.as_object().unwrap();
    // core §0.1's field-presence rule: in_reply_to/session/delegation are
    // ALWAYS-present keys, null when unset — never simply absent (this is
    // the exact bug class flagged in the porting spec re: Go's non-
    // omitempty *string/[]T fields).
    assert!(obj.contains_key("in_reply_to"));
    assert_eq!(obj["in_reply_to"], serde_json::Value::Null);
    assert!(obj.contains_key("session"));
    assert_eq!(obj["session"], serde_json::Value::Null);
    assert!(obj.contains_key("delegation"));
    assert_eq!(
        obj["delegation"],
        serde_json::Value::Null,
        "a nil Go slice marshals to JSON null, not []"
    );
    assert!(!obj.contains_key("sig"), "sig is omitempty and unset here");
}

#[test]
fn envelope_ttl_bounds_are_enforced() {
    let mut e = Envelope {
        awp: "0.1".to_string(),
        id: awp::envelope::new_id(),
        kind: "message".to_string(),
        from: "a.example.com".to_string(),
        to: "b.example.com".to_string(),
        thread: awp::envelope::new_id(),
        in_reply_to: None,
        ts: identity::now_rfc3339_milli(),
        ttl: 59,
        session: None,
        delegation: None,
        body: json!({}),
        sig: None,
    };
    assert!(e.validate_ttl().is_err(), "59 < MIN_TTL(60) must reject");
    e.ttl = 604801;
    assert!(
        e.validate_ttl().is_err(),
        "604801 > MAX_TTL(604800) must reject"
    );
    e.ttl = 3600;
    assert!(e.validate_ttl().is_ok());
}

#[test]
fn envelope_size_cap_is_enforced() {
    let signing_key = fresh_key();
    let big_text = "x".repeat(300 * 1024);
    let mut e = Envelope {
        awp: "0.1".to_string(),
        id: awp::envelope::new_id(),
        kind: "message".to_string(),
        from: "a.example.com".to_string(),
        to: "b.example.com".to_string(),
        thread: awp::envelope::new_id(),
        in_reply_to: None,
        ts: identity::now_rfc3339_milli(),
        ttl: 3600,
        session: None,
        delegation: None,
        body: json!({ "text": big_text }),
        sig: None,
    };
    e.sign(&signing_key, "k1").unwrap();
    assert!(e.validate_size().is_err());
}

fn signed_index(domain: &str, signing_key: &ed25519_dalek::SigningKey, kid: &str) -> Index {
    let mut idx = Index {
        awp: "0.1".to_string(),
        domain: domain.to_string(),
        updated: identity::now_rfc3339_milli(),
        keys: Some(vec![Key {
            kid: kid.to_string(),
            alg: "ed25519".to_string(),
            pub_: awp::b64::url_encode(signing_key.verifying_key().as_bytes()),
            created: identity::now_rfc3339_milli(),
            expires: None,
            revoked: false,
            prev_sig: None,
        }]),
        entities: Some(vec![Entity {
            name: format!("{domain}#agent"),
            kind: "agent".to_string(),
            manifest: format!("https://{domain}/manifest.json"),
            manifest_sha256: "deadbeef".to_string(),
        }]),
        inbox: format!("https://{domain}/awp/inbox"),
        peers: None,
        crawl: None,
        transports: Some(vec![Transport {
            proto: "https".to_string(),
            endpoint: format!("https://{domain}"),
        }]),
        sig: None,
    };
    idx.sign(signing_key, kid).expect("sign index");
    idx
}

#[test]
fn index_self_signature_round_trips() {
    let signing_key = fresh_key();
    let idx = signed_index("example.com", &signing_key, "k1");
    idx.verify_self_sig().expect("verify_self_sig");
}

#[test]
fn index_self_signature_rejects_tampering() {
    let signing_key = fresh_key();
    let mut idx = signed_index("example.com", &signing_key, "k1");
    idx.inbox = "https://evil.example.com/awp/inbox".to_string();
    assert!(idx.verify_self_sig().is_err());
}

#[test]
fn index_null_vs_empty_keys_entities_distinction_is_preserved() {
    let idx_nil = Index {
        awp: "0.1".to_string(),
        domain: "example.com".to_string(),
        updated: identity::now_rfc3339_milli(),
        keys: None,
        entities: None,
        inbox: String::new(),
        peers: None,
        crawl: None,
        transports: None,
        sig: None,
    };
    let v = serde_json::to_value(&idx_nil).unwrap();
    assert_eq!(v["keys"], serde_json::Value::Null);
    assert_eq!(v["entities"], serde_json::Value::Null);
    assert!(
        v.as_object().unwrap().contains_key("inbox"),
        "inbox has no omitempty tag on the Go side"
    );

    let idx_empty = Index {
        keys: Some(vec![]),
        entities: Some(vec![]),
        ..idx_nil
    };
    let v2 = serde_json::to_value(&idx_empty).unwrap();
    assert_eq!(v2["keys"], serde_json::json!([]));
    assert_eq!(v2["entities"], serde_json::json!([]));

    // These two must NOT canonicalize to the same bytes.
    assert_ne!(awp::jcs::canonicalize(&v), awp::jcs::canonicalize(&v2));
}

#[test]
fn index_revoked_key_resolution_is_rejected_by_client_resolve_semantics() {
    // Client::resolve's revocation check is exercised end-to-end in
    // client_test.rs-equivalent coverage (see roundtrip_client.rs); here we
    // just confirm the wire shape survives round-trip with revoked:true
    // (a plain, always-present bool per core §1.1, no omitempty).
    let key = Key {
        kid: "k1".to_string(),
        alg: "ed25519".to_string(),
        pub_: "deadbeef".to_string(),
        created: identity::now_rfc3339_milli(),
        expires: None,
        revoked: true,
        prev_sig: None,
    };
    let v = serde_json::to_value(&key).unwrap();
    assert_eq!(v["revoked"], serde_json::json!(true));
    assert_eq!(v["expires"], serde_json::Value::Null);
    assert_eq!(v["prev_sig"], serde_json::Value::Null);
    assert_eq!(
        v["pub"],
        serde_json::json!("deadbeef"),
        "the reserved-word field renames to \"pub\" on the wire"
    );
}

#[test]
fn manifest_round_trips_sign_and_verify() {
    let signing_key = fresh_key();
    let mut m = Manifest {
        awp: "0.1".to_string(),
        name: "tool.example.com#doubler".to_string(),
        kind: "tool".to_string(),
        version: "1.0.0".to_string(),
        updated: identity::now_rfc3339_milli(),
        description: "doubles a number".to_string(),
        io: IoSchema::default(),
        distribution: Distribution {
            hosted: Some(Hosted {
                endpoint: "https://tool.example.com/awp/tools/doubler".to_string(),
            }),
            portable: None,
        },
        state: "stateless".to_string(),
        auth: Auth {
            sig: "required".to_string(),
            scopes: None,
        },
        pricing: serde_json::Value::Null,
        inbox: None,
        sig: None,
    };
    m.sign(&signing_key, "k1").expect("sign");
    m.verify(&signing_key.verifying_key()).expect("verify");
}

#[test]
fn manifest_pin_check_happens_on_raw_bytes_before_parsing() {
    let signing_key = fresh_key();
    let mut m = Manifest {
        awp: "0.1".to_string(),
        name: "tool.example.com#doubler".to_string(),
        kind: "tool".to_string(),
        version: "1.0.0".to_string(),
        updated: identity::now_rfc3339_milli(),
        description: "".to_string(),
        io: IoSchema::default(),
        distribution: Distribution::default(),
        state: "stateless".to_string(),
        auth: Auth {
            sig: "required".to_string(),
            scopes: None,
        },
        pricing: serde_json::Value::Null,
        inbox: None,
        sig: None,
    };
    m.sign(&signing_key, "k1").unwrap();
    let raw = serde_json::to_vec(&m).unwrap();

    let mut hasher_input = raw.clone();
    // A swapped manifest (any byte changed post-signing) must fail the pin
    // check, which operates on raw bytes — not the signature check, which
    // would also fail but for a different reason and must never be
    // reached first per core §1.2's doc comment.
    hasher_input.push(b' ');
    let real_hex = {
        use sha2::{Digest, Sha256};
        let sum = Sha256::digest(&raw);
        hex_encode(&sum)
    };
    assert!(awp::manifest::verify_pinned_sha256(&raw, &real_hex).is_ok());
    assert!(awp::manifest::verify_pinned_sha256(&hasher_input, &real_hex).is_err());
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signed_link(
    delegator_key: &ed25519_dalek::SigningKey,
    delegator: &str,
    delegate: &str,
    scope: Scope,
    expires: &str,
    nonce: &str,
    kid: &str,
) -> Link {
    let mut link = Link {
        delegator: delegator.to_string(),
        delegate: delegate.to_string(),
        scope,
        expires: expires.to_string(),
        nonce: nonce.to_string(),
        sig: None,
    };
    link.sign(delegator_key, kid).expect("sign link");
    link
}

struct MapResolver(std::collections::HashMap<(String, String), ed25519_dalek::VerifyingKey>);

impl delegation::KeyResolver for MapResolver {
    fn resolve(&self, domain: &str, kid: &str) -> Result<ed25519_dalek::VerifyingKey, String> {
        self.0
            .get(&(domain.to_string(), kid.to_string()))
            .copied()
            .ok_or_else(|| "not found".to_string())
    }
}

#[test]
fn delegation_link_round_trips_sign_and_verify() {
    let signing_key = fresh_key();
    let link = signed_link(
        &signing_key,
        "delegator.example.com",
        "delegate.example.com",
        Scope::default(),
        "2099-01-01T00:00:00Z",
        &awp::envelope::new_id(),
        "k1",
    );
    identity::verify_sig(&link, link.sig.as_ref(), &signing_key.verifying_key()).expect("verify");
}

#[test]
fn delegation_empty_chain_is_not_a_violation() {
    let resolver = MapResolver(Default::default());
    let input = delegation::VerifyInput {
        chain: &[],
        from: "someone.example.com",
        to: "provider.example.com#tool",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    assert!(delegation::verify(&input).is_ok());
}

#[test]
fn delegation_chain_too_long_rejects() {
    let signing_key = fresh_key();
    let mut chain = Vec::new();
    // Build 9 links (> MaxChainLength=8), continuity satisfied so the
    // length check is the only thing that can fire.
    for i in 0..9 {
        let scope = if i == 0 {
            Scope {
                to: Some("x".to_string()),
                ..Default::default()
            }
        } else {
            Scope::default()
        };
        chain.push(signed_link(
            &signing_key,
            "d.example.com",
            "d.example.com",
            scope,
            "2099-01-01T00:00:00Z",
            &awp::envelope::new_id(),
            "k1",
        ));
    }
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("d.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: &chain,
        from: "d.example.com",
        to: "x",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("9-link chain must reject");
    assert_eq!(err.rule, delegation::RULE_CHAIN_TOO_LONG);
    assert_eq!(err.link_index, -1);
}

#[test]
fn delegation_root_scope_unbounded_rejects_when_unscoped_and_long_lived() {
    let signing_key = fresh_key();
    let nonce = awp::envelope::new_id(); // "now"-ish ULID
    let far_future = "2099-01-01T00:00:00Z"; // far beyond nonce + 24h
    let link = signed_link(
        &signing_key,
        "root.example.com",
        "someone.example.com",
        Scope::default(),
        far_future,
        &nonce,
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: std::slice::from_ref(&link),
        from: "someone.example.com",
        to: "provider.example.com#tool",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("unscoped root with >24h lifetime must reject");
    assert_eq!(err.rule, delegation::RULE_ROOT_SCOPE_UNBOUNDED);
}

#[test]
fn delegation_root_scope_bound_ok_when_scoped_to() {
    let signing_key = fresh_key();
    let nonce = awp::envelope::new_id();
    let link = signed_link(
        &signing_key,
        "root.example.com",
        "someone.example.com",
        Scope {
            to: Some("provider.example.com#tool".to_string()),
            ..Default::default()
        },
        "2099-01-01T00:00:00Z",
        &nonce,
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: std::slice::from_ref(&link),
        from: "someone.example.com",
        to: "provider.example.com#tool",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    assert!(
        delegation::verify(&input).is_ok(),
        "a `to`-scoped root has no duration bound"
    );
}

#[test]
fn delegation_signature_rule_rejects_bad_signature() {
    let signing_key = fresh_key();
    let wrong_key = fresh_key();
    let link = signed_link(
        &signing_key,
        "root.example.com",
        "someone.example.com",
        Scope {
            to: Some("x".to_string()),
            ..Default::default()
        },
        "2099-01-01T00:00:00Z",
        &awp::envelope::new_id(),
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        wrong_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: std::slice::from_ref(&link),
        from: "someone.example.com",
        to: "x",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("wrong resolver key must fail signature check");
    assert_eq!(err.rule, delegation::RULE_BAD_SIGNATURE);
}

#[test]
fn delegation_expiry_rule_rejects_expired_link() {
    let signing_key = fresh_key();
    let link = signed_link(
        &signing_key,
        "root.example.com",
        "someone.example.com",
        Scope {
            to: Some("x".to_string()),
            ..Default::default()
        },
        "2000-01-01T00:00:00Z", // long expired
        &awp::envelope::new_id(),
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: std::slice::from_ref(&link),
        from: "someone.example.com",
        to: "x",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("expired link must reject");
    assert_eq!(err.rule, delegation::RULE_EXPIRED);
}

#[test]
fn delegation_continuity_rule_rejects_broken_chain() {
    let signing_key = fresh_key();
    let link0 = signed_link(
        &signing_key,
        "root.example.com",
        "middle.example.com",
        Scope {
            to: Some("x".to_string()),
            ..Default::default()
        },
        "2099-01-01T00:00:00Z",
        &awp::envelope::new_id(),
        "k1",
    );
    // link1's delegator is NOT link0's delegate -> continuity violation.
    let link1 = signed_link(
        &signing_key,
        "someone-else.example.com",
        "final.example.com",
        Scope::default(),
        "2099-01-01T00:00:00Z",
        &awp::envelope::new_id(),
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    keys.insert(
        ("someone-else.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let chain = vec![link0, link1];
    let input = delegation::VerifyInput {
        chain: &chain,
        from: "final.example.com",
        to: "x",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("broken continuity must reject");
    assert_eq!(err.rule, delegation::RULE_CONTINUITY);
    assert_eq!(err.link_index, 1);
}

#[test]
fn delegation_final_delegate_rule_rejects_mismatch() {
    let signing_key = fresh_key();
    let link = signed_link(
        &signing_key,
        "root.example.com",
        "middle.example.com",
        Scope {
            to: Some("x".to_string()),
            ..Default::default()
        },
        "2099-01-01T00:00:00Z",
        &awp::envelope::new_id(),
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: std::slice::from_ref(&link),
        from: "not-middle.example.com", // != link.delegate
        to: "x",
        kind: "message",
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("final delegate mismatch must reject");
    assert_eq!(err.rule, delegation::RULE_FINAL_DELEGATE);
}

#[test]
fn delegation_scope_intersection_rule_rejects_out_of_scope_kind() {
    let signing_key = fresh_key();
    let link = signed_link(
        &signing_key,
        "root.example.com",
        "someone.example.com",
        Scope {
            to: Some("x".to_string()),
            kinds: Some(vec!["message".to_string()]),
            body_types: None,
        },
        "2099-01-01T00:00:00Z",
        &awp::envelope::new_id(),
        "k1",
    );
    let mut keys = std::collections::HashMap::new();
    keys.insert(
        ("root.example.com".to_string(), "k1".to_string()),
        signing_key.verifying_key(),
    );
    let resolver = MapResolver(keys);
    let input = delegation::VerifyInput {
        chain: std::slice::from_ref(&link),
        from: "someone.example.com",
        to: "x",
        kind: "reply", // not in scope.kinds
        body_type: "text",
        now: SystemTime::now(),
        resolve_key: &resolver,
    };
    let err = delegation::verify(&input).expect_err("out-of-scope kind must reject");
    assert_eq!(err.rule, delegation::RULE_SCOPE_INTERSECTION);
}

#[test]
fn delegation_link_expires_has_no_fractional_seconds() {
    let signing_key = fresh_key();
    let expires = SystemTime::now() + Duration::from_secs(3600);
    let formatted = awp::rfc3339::format_no_fraction(expires);
    assert!(
        !formatted.contains('.'),
        "delegation Link.expires must use bare RFC3339, no milliseconds: got {formatted:?}"
    );
    assert!(formatted.ends_with('Z'));
    let link = signed_link(
        &signing_key,
        "d.example.com",
        "e.example.com",
        Scope::default(),
        &formatted,
        &awp::envelope::new_id(),
        "k1",
    );
    assert_eq!(link.expires, formatted);
}

#[test]
fn rotation_chain_round_trips_with_valid_links() {
    let root_key = fresh_key();
    let next_key = fresh_key();
    let sig = ed25519_dalek::Signer::sign(&root_key, next_key.verifying_key().as_bytes());
    let chain = vec![
        Key {
            kid: "k1".to_string(),
            alg: "ed25519".to_string(),
            pub_: awp::b64::url_encode(root_key.verifying_key().as_bytes()),
            created: identity::now_rfc3339_milli(),
            expires: None,
            revoked: false,
            prev_sig: None,
        },
        Key {
            kid: "k2".to_string(),
            alg: "ed25519".to_string(),
            pub_: awp::b64::url_encode(next_key.verifying_key().as_bytes()),
            created: identity::now_rfc3339_milli(),
            expires: None,
            revoked: false,
            prev_sig: Some(awp::b64::url_encode(&sig.to_bytes())),
        },
    ];
    identity::verify_rotation_chain(&chain).expect("valid rotation chain must verify");
}

#[test]
fn rotation_chain_rejects_broken_link() {
    let root_key = fresh_key();
    let next_key = fresh_key();
    let unrelated_key = fresh_key();
    // Sign the WRONG key's bytes -- prev_sig doesn't actually attest to
    // next_key's pubkey.
    let bad_sig = ed25519_dalek::Signer::sign(&root_key, unrelated_key.verifying_key().as_bytes());
    let chain = vec![
        Key {
            kid: "k1".to_string(),
            alg: "ed25519".to_string(),
            pub_: awp::b64::url_encode(root_key.verifying_key().as_bytes()),
            created: identity::now_rfc3339_milli(),
            expires: None,
            revoked: false,
            prev_sig: None,
        },
        Key {
            kid: "k2".to_string(),
            alg: "ed25519".to_string(),
            pub_: awp::b64::url_encode(next_key.verifying_key().as_bytes()),
            created: identity::now_rfc3339_milli(),
            expires: None,
            revoked: false,
            prev_sig: Some(awp::b64::url_encode(&bad_sig.to_bytes())),
        },
    ];
    let err =
        identity::verify_rotation_chain(&chain).expect_err("broken rotation link must reject");
    assert_eq!(err.index, 1);
}
