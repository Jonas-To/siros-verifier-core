//! Request-signing key rotation through the public endpoints: a stored
//! pre-rotation flow is re-signed (`request_uri_method = "post"` — a wallet
//! POSTs `wallet_nonce`) by the pair it was created under, matched by its
//! stored request object's `x5c` leaf, so the re-issued request carries
//! the chain its `client_id` hashes from.
//!
//! The rotation models a restart: the old process (generation A) starts
//! a flow into a shared store; the new process (generation B current, A
//! retained) completes that same flow. The re-sign goes through the
//! public `request` endpoint — nothing private, nothing re-implemented.

use std::collections::BTreeMap;
use std::sync::Arc;

use tunnelbana_core::context::Context;
use tunnelbana_core::http::HttpRequestData;
use tunnelbana_core::internal::InternalData;
use tunnelbana_core::plugin::{Backend, BackendAction};
use tunnelbana_core::state::State;

use siros_verifier_core::session_seal::SessionSealer;
use siros_verifier_core::testutil;
use siros_verifier_core_tunnelbana::{
    system_clock, MemoryFlowStore, NoPdp, TrustGate, VpBackend, VpBackendConfig,
};

const NS: &str = "VP_BACKEND";
const FLOW_KEY: &str = "flow_id";

/// One request-signing key generation: its self-signed chain (a stand-in
/// for the real WRPAC chain) and the JWK used to sign its request objects.
struct Generation {
    chain: Vec<Vec<u8>>,
    jwk: jose_rs::jwk::Jwk,
}

impl Generation {
    fn new(dns: &str) -> Self {
        let (der, jwk) = testutil::self_signed_ec(dns, "ES256");
        Self {
            chain: vec![der],
            jwk,
        }
    }

    fn signer(&self) -> kryptering::SoftwareSigner {
        siros_verifier_core::oid4vp::software_signer(&self.jwk).unwrap()
    }

    /// The public JWK that verifies this generation's signatures.
    fn public_jwk(&self) -> jose_rs::jwk::Jwk {
        testutil::public_of(&self.jwk)
    }
}

fn backend(
    current: &Generation,
    previous: Option<&Generation>,
    store: Option<Arc<MemoryFlowStore>>,
    sealer: Option<SessionSealer>,
) -> VpBackend {
    let cfg: VpBackendConfig = serde_json::from_value(serde_json::json!({
        "dcql": {"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:example:pid:1"]},
            "claims": [{"path": ["credentialSubject", "given_name"]}]}]},
        "attribute_map": {"givenname": "/given_name"},
        "subject_pointer": "/family_name",
        "role": "pid-provider"
    }))
    .unwrap();
    let gate = TrustGate::new(
        Arc::new(NoPdp),
        p256::ecdsa::SigningKey::from_slice(&[0x42; 32]).expect("test scalar"),
        "test-kid",
        "test-issuer",
        "test-audience",
        "test-pdp",
        300,
    );
    let mut backend = VpBackend::new(
        "vp",
        "https://proxy.example/vp",
        cfg,
        gate,
        current.signer(),
        current.chain.clone(),
        system_clock(),
    )
    .unwrap();
    if let Some(store) = store {
        backend = backend.with_flow_store(store);
    }
    if let Some(sealer) = sealer {
        backend = backend.with_session_sealer(sealer);
    }
    if let Some(previous) = previous {
        backend = backend
            .with_previous_request_signers(vec![(previous.signer(), previous.chain.clone())])
            .unwrap();
    }
    backend
}

/// Start a flow through the public `start` endpoint, as the UI does.
async fn start(b: &VpBackend, requester: &str) -> (State, String) {
    let mut ctx = Context::new(
        HttpRequestData {
            path: "vp/start".into(),
            method: "GET".into(),
            ..Default::default()
        },
        State::new(),
    );
    let mut request = InternalData::request(requester);
    request.set_attr(
        "dcql",
        serde_json::json!({"credentials": [{"id": "pid", "format": "dc+sd-jwt",
            "meta": {"vct_values": ["urn:example:pid:1"]},
            "claims": [{"path": ["credentialSubject", "given_name"]}]}]})
        .to_string(),
    );
    b.start_auth(&mut ctx, request).await.unwrap();
    let id = ctx.state.get_str(NS, FLOW_KEY).unwrap();
    (ctx.state, id)
}

/// A wallet's POSTed wallet_nonce, as the request endpoint sees it.
async fn post_nonce(b: &VpBackend, id: &str, nonce: &str) -> Result<(u16, String), String> {
    let mut r = HttpRequestData {
        path: format!("vp/request/{id}"),
        method: "POST".into(),
        ..Default::default()
    };
    r.form = BTreeMap::from([("wallet_nonce".to_string(), nonce.to_string())]);
    r.form_pairs = vec![("wallet_nonce".into(), nonce.into())];
    let mut ctx = Context::new(r, State::new());
    match b.handle_endpoint(&mut ctx, "request").await {
        Ok(BackendAction::Respond(resp)) => Ok((
            resp.status,
            String::from_utf8(resp.body).map_err(|e| e.to_string())?,
        )),
        Ok(_) => Err("a non-respond action on the request endpoint".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// The `x5c` chain a request object carries, DER-encoded.
fn jar_chain(jar: &str) -> Vec<Vec<u8>> {
    let header = jose_rs::jws::decode_header(jar).unwrap();
    header
        .x5c
        .unwrap()
        .iter()
        // x5c is standard base64 (the same engine the re-sign embeds with).
        .map(|b| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(b).unwrap()
        })
        .collect()
}

/// The request object's payload.
fn jar_payload(jar: &str) -> serde_json::Value {
    let payload = jar.split('.').nth(1).unwrap();
    serde_json::from_slice(&jose_rs::base64url::decode(payload).unwrap()).unwrap()
}

/// The shared fixtures: one flow store and one sealer across both
/// process generations (a restart keeps both).
struct Shared {
    store: Arc<MemoryFlowStore>,
    sealer: SessionSealer,
}

fn shared() -> Shared {
    Shared {
        store: Arc::new(MemoryFlowStore::default()),
        sealer: SessionSealer::from_master(&[41u8; 32], "vp").unwrap(),
    }
}

#[tokio::test]
async fn a_flow_started_before_the_rotation_is_re_signed_by_its_own_generation() {
    // The old process: generation A signs new flows.
    let a = Generation::new("old.example");
    let s = shared();
    let old = backend(&a, None, Some(s.store.clone()), Some(sealer_of(&s.sealer)));

    // A flow starts under generation A, then the process restarts with
    // generation B current and A retained.
    let (_state, id) = start(&old, "qr").await;
    let b = Generation::new("new.example");
    let new = backend(
        &b,
        Some(&a),
        Some(s.store.clone()),
        Some(sealer_of(&s.sealer)),
    );

    // The wallet POSTs the flow's request with its nonce — through the
    // public endpoint.
    let (status, jar) = post_nonce(&new, &id, "wallet-nonce-1")
        .await
        .expect("the pre-rotation flow re-signs");
    assert_eq!(status, 200);

    // The re-issued request object carries the wallet_nonce...
    assert_eq!(jar_payload(&jar)["wallet_nonce"], "wallet-nonce-1");
    // ...and generation A's chain, embedded by the pair the flow was
    // created under — not generation B's.
    assert_eq!(jar_chain(&jar), a.chain);
    assert_ne!(jar_chain(&jar), b.chain);
    // The signature verifies under generation A's public key.
    let verified = jose_rs::jws::compact::verify_with_jwk(&a.public_jwk(), &jar);
    assert!(
        verified.is_ok(),
        "the re-signed request verifies under the generation it was created with"
    );
}

#[tokio::test]
async fn a_flow_started_after_the_rotation_is_re_signed_by_the_current_generation() {
    let b = Generation::new("new.example");
    let a = Generation::new("old.example");
    let s = shared();
    let new = backend(
        &b,
        Some(&a),
        Some(s.store.clone()),
        Some(sealer_of(&s.sealer)),
    );

    let (_state, id) = start(&new, "qr").await;
    let (status, jar) = post_nonce(&new, &id, "wallet-nonce-2")
        .await
        .expect("the current flow re-signs");
    assert_eq!(status, 200);
    assert_eq!(jar_chain(&jar), b.chain);
    let verified = jose_rs::jws::compact::verify_with_jwk(&b.public_jwk(), &jar);
    assert!(
        verified.is_ok(),
        "the re-signed request verifies under the current generation"
    );
}

#[tokio::test]
async fn a_flow_from_a_generation_outside_the_window_is_refused() {
    // The rotation window passed: generation A started the flow, but the
    // new process retains no previous pair.
    let a = Generation::new("old.example");
    let s = shared();
    let old = backend(&a, None, Some(s.store.clone()), Some(sealer_of(&s.sealer)));
    let (_state, id) = start(&old, "qr").await;

    let b = Generation::new("new.example");
    let new = backend(&b, None, Some(s.store.clone()), Some(sealer_of(&s.sealer)));

    let err = post_nonce(&new, &id, "wallet-nonce-3")
        .await
        .expect_err("a flow past the rotation window must be refused");
    assert!(
        err.contains("rotation window"),
        "the refusal names the window: {err}"
    );
}

#[tokio::test]
async fn the_retained_pair_is_validated_at_build() {
    // The builder is public API: a duplicate leaf between the current and
    // a previous chain would make generation matching ambiguous, and an
    // empty chain carries no leaf to match — both refused.
    let b = Generation::new("new.example");
    let a = Generation::new("old.example");
    let built = backend(&b, None, None, None);
    let err = match built.with_previous_request_signers(vec![(a.signer(), b.chain.clone())]) {
        Ok(_) => panic!("a duplicate leaf must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("duplicates"),
        "the error names the ambiguity: {err}"
    );

    let built = backend(&b, None, None, None);
    let err = match built.with_previous_request_signers(vec![(a.signer(), Vec::new())]) {
        Ok(_) => panic!("an empty previous chain must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("chain is empty"),
        "the error names the empty chain: {err}"
    );
}

/// A cloneable sealer handle for the shared fixture (the sealer type is
/// not Clone; rebuild it from the same master).
fn sealer_of(sealer: &SessionSealer) -> SessionSealer {
    // from_master is deterministic: the same master and tenant produce
    // an equivalent sealer.
    let master = [41u8; 32];
    let _ = sealer;
    SessionSealer::from_master(&master, "vp").unwrap()
}
