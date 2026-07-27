//! Chain verification for AWP delegation proofs per core §2.5.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::identity::{self, domain_of, IdentityError, Sig};

/// core §2.5 rule 6.
pub const MAX_CHAIN_LENGTH: usize = 8;

/// Restricts what a delegate may do on the delegator's behalf. Absent
/// fields mean unrestricted for that field (core §2.5). Unlike
/// Envelope/Index's non-omitempty convention, Scope's fields ARE omitempty
/// on the Go side — absent, not null, when unset.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Scope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_types: Option<Vec<String>>,
}

impl Scope {
    fn is_entirely_unscoped_to(&self) -> bool {
        self.to.is_none()
    }
}

/// One entry of a delegation chain (core §2.5). `expires` uses bare
/// RFC3339 (time.RFC3339 on the Go side) — NO fractional seconds, unlike
/// Envelope/Index timestamps, which are always millisecond-precision. Using
/// the wrong formatter here produces different signed bytes than a Go peer
/// expects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    pub delegator: String,
    pub delegate: String,
    pub scope: Scope,
    pub expires: String,
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<Sig>,
}

impl Link {
    /// Attaches l.sig per core §0.1, signed by the delegator's domain key.
    pub fn sign(&mut self, signing_key: &SigningKey, kid: &str) -> Result<(), IdentityError> {
        self.sig = Some(identity::sign(self, signing_key, kid)?);
        Ok(())
    }
}

/// Rule names identify which core §2.5 validity rule failed.
pub const RULE_CHAIN_TOO_LONG: &str = "chain_too_long"; // rule 6
pub const RULE_ROOT_SCOPE_UNBOUNDED: &str = "root_scope_unbounded"; // rule 5 (root-link special case)
pub const RULE_BAD_SIGNATURE: &str = "signature"; // rule 1
pub const RULE_EXPIRED: &str = "expiry"; // rule 3
pub const RULE_CONTINUITY: &str = "continuity"; // rule 2
pub const RULE_FINAL_DELEGATE: &str = "final_delegate"; // rule 4
pub const RULE_SCOPE_INTERSECTION: &str = "scope_intersection"; // rule 5

/// Identifies exactly which core §2.5 rule rejected a chain, and at which
/// link (-1 when not link-specific).
#[derive(Debug, Clone, thiserror::Error)]
pub struct RuleViolation {
    pub rule: String,
    pub link_index: i64,
    pub detail: String,
}

impl std::fmt::Display for RuleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.link_index < 0 {
            write!(
                f,
                "delegation: rule {:?} violated: {}",
                self.rule, self.detail
            )
        } else {
            write!(
                f,
                "delegation: rule {:?} violated at link {}: {}",
                self.rule, self.link_index, self.detail
            )
        }
    }
}

/// Resolves a domain+kid to the domain's currently trusted public key (via
/// that domain's index, out of scope for this module).
pub trait KeyResolver {
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String>;
}

impl<F> KeyResolver for F
where
    F: Fn(&str, &str) -> Result<VerifyingKey, String>,
{
    fn resolve(&self, domain: &str, kid: &str) -> Result<VerifyingKey, String> {
        self(domain, kid)
    }
}

/// Bundles the envelope (or sync-call) context a chain is checked against.
pub struct VerifyInput<'a> {
    pub chain: &'a [Link],
    pub from: &'a str,
    pub to: &'a str,
    pub kind: &'a str,
    pub body_type: &'a str,
    pub now: SystemTime,
    pub resolve_key: &'a dyn KeyResolver,
}

/// Runs every core §2.5 validity rule against the chain, short-circuiting
/// on the first violation and identifying it specifically. An empty chain
/// is not itself a violation — it means no delegation is being asserted;
/// callers only invoke verify when the envelope claims delegated authority.
pub fn verify(input: &VerifyInput) -> Result<(), RuleViolation> {
    if input.chain.is_empty() {
        return Ok(());
    }
    if input.chain.len() > MAX_CHAIN_LENGTH {
        return Err(RuleViolation {
            rule: RULE_CHAIN_TOO_LONG.to_string(),
            link_index: -1,
            detail: format!(
                "chain has {} links, max {}",
                input.chain.len(),
                MAX_CHAIN_LENGTH
            ),
        });
    }

    verify_root_scope_bound(&input.chain[0])?;

    for (i, link) in input.chain.iter().enumerate() {
        verify_link_signature(input.resolve_key, link, i)?;
        verify_link_unexpired(link, input.now, i)?;
        if i > 0 {
            let prev = &input.chain[i - 1];
            if prev.delegate != link.delegator {
                return Err(RuleViolation {
                    rule: RULE_CONTINUITY.to_string(),
                    link_index: i as i64,
                    detail: format!(
                        "link {} delegate {:?} != link {} delegator {:?}",
                        i - 1,
                        prev.delegate,
                        i,
                        link.delegator
                    ),
                });
            }
        }
    }

    let last = input.chain.last().unwrap();
    if last.delegate != input.from {
        return Err(RuleViolation {
            rule: RULE_FINAL_DELEGATE.to_string(),
            link_index: (input.chain.len() - 1) as i64,
            detail: format!(
                "final delegate {:?} != envelope from {:?}",
                last.delegate, input.from
            ),
        });
    }

    verify_scope_intersection(input.chain, input.to, input.kind, input.body_type)?;

    Ok(())
}

/// Enforces core §2.5 rule 5's root-link special case: an entirely empty
/// root scope is invalid — root links MUST either scope `to` or carry
/// expires <= 24h from issuance. Root link duration is measured from the
/// link's nonce (a ULID, which embeds its own creation time) to its
/// expiry.
fn verify_root_scope_bound(root: &Link) -> Result<(), RuleViolation> {
    if !root.scope.is_entirely_unscoped_to() {
        return Ok(());
    }
    let nonce_time = decode_ulid_time(&root.nonce).map_err(|e| RuleViolation {
        rule: RULE_ROOT_SCOPE_UNBOUNDED.to_string(),
        link_index: 0,
        detail: format!("root link has no `to` scope and nonce is not a valid ULID: {e}"),
    })?;
    let expires_time = parse_rfc3339(&root.expires).map_err(|e| RuleViolation {
        rule: RULE_ROOT_SCOPE_UNBOUNDED.to_string(),
        link_index: 0,
        detail: format!("root link has no `to` scope and expires is not valid RFC3339: {e}"),
    })?;
    let diff = expires_time
        .duration_since(nonce_time)
        .unwrap_or(std::time::Duration::from_secs(0));
    if expires_time > nonce_time && diff > std::time::Duration::from_secs(24 * 3600) {
        return Err(RuleViolation {
            rule: RULE_ROOT_SCOPE_UNBOUNDED.to_string(),
            link_index: 0,
            detail: "root link has no `to` scope and expires > 24h after issuance".to_string(),
        });
    }
    Ok(())
}

fn decode_ulid_time(nonce: &str) -> Result<SystemTime, String> {
    let id = ulid::Ulid::from_string(&nonce.to_uppercase()).map_err(|e| e.to_string())?;
    Ok(id.datetime())
}

/// Parses a bare RFC3339 timestamp (no fractional seconds expected, but
/// tolerated on parse the same way Go's time.Parse(time.RFC3339, ...)
/// tolerates them) into a SystemTime.
pub fn parse_rfc3339(s: &str) -> Result<SystemTime, String> {
    crate::rfc3339::parse(s)
}

fn verify_link_signature(
    resolve: &dyn KeyResolver,
    link: &Link,
    index: usize,
) -> Result<(), RuleViolation> {
    let Some(sig) = &link.sig else {
        return Err(RuleViolation {
            rule: RULE_BAD_SIGNATURE.to_string(),
            link_index: index as i64,
            detail: "missing sig".to_string(),
        });
    };
    let pub_key = resolve
        .resolve(&domain_of(&link.delegator), &sig.kid)
        .map_err(|e| RuleViolation {
            rule: RULE_BAD_SIGNATURE.to_string(),
            link_index: index as i64,
            detail: format!("resolve delegator key: {e}"),
        })?;
    identity::verify_sig(link, link.sig.as_ref(), &pub_key).map_err(|e| RuleViolation {
        rule: RULE_BAD_SIGNATURE.to_string(),
        link_index: index as i64,
        detail: e.to_string(),
    })
}

fn verify_link_unexpired(link: &Link, now: SystemTime, index: usize) -> Result<(), RuleViolation> {
    let expires_time = parse_rfc3339(&link.expires).map_err(|e| RuleViolation {
        rule: RULE_EXPIRED.to_string(),
        link_index: index as i64,
        detail: format!("expires is not valid RFC3339: {e}"),
    })?;
    if now > expires_time {
        return Err(RuleViolation {
            rule: RULE_EXPIRED.to_string(),
            link_index: index as i64,
            detail: "link expired".to_string(),
        });
    }
    Ok(())
}

fn verify_scope_intersection(
    chain: &[Link],
    to: &str,
    kind: &str,
    body_type: &str,
) -> Result<(), RuleViolation> {
    for (i, link) in chain.iter().enumerate() {
        if let Some(scope_to) = &link.scope.to {
            if scope_to != to {
                return Err(RuleViolation {
                    rule: RULE_SCOPE_INTERSECTION.to_string(),
                    link_index: i as i64,
                    detail: format!("scope.to {:?} excludes envelope to {:?}", scope_to, to),
                });
            }
        }
        if let Some(kinds) = &link.scope.kinds {
            if !kinds.is_empty() && !kinds.iter().any(|k| k == kind) {
                return Err(RuleViolation {
                    rule: RULE_SCOPE_INTERSECTION.to_string(),
                    link_index: i as i64,
                    detail: format!("scope.kinds {:?} excludes envelope kind {:?}", kinds, kind),
                });
            }
        }
        if let Some(body_types) = &link.scope.body_types {
            if !body_types.is_empty() && !body_types.iter().any(|b| b == body_type) {
                return Err(RuleViolation {
                    rule: RULE_SCOPE_INTERSECTION.to_string(),
                    link_index: i as i64,
                    detail: format!(
                        "scope.body_types {:?} excludes envelope body type {:?}",
                        body_types, body_type
                    ),
                });
            }
        }
    }
    Ok(())
}
