//! The VC-layout adapter: the gdc deployment's actual vc-stack verifier
//! configuration is the acceptance fixture. The translation must place
//! every member of that document in a taxonomy bucket (mapped or
//! known-unsupported — never silently dropped), and the emitted
//! proxy.toml must be a real, bootable service configuration.

use siros_verifier_service::vc_layout;

const GDC: &str = include_str!("../testdata/vc-layout/gdc.yaml");

#[test]
fn the_gdc_layout_translates_with_no_unknown_members() {
    let translation = vc_layout::translate(GDC).expect("the gdc layout translates");
    // The taxonomy walk found no unknown members (translate would have
    // refused), and the report records both mapped and warned paths.
    assert!(!translation.report.mapped.is_empty());
    assert!(!translation.report.warned.is_empty());
}

#[test]
fn the_gdc_layouts_known_unsupported_capabilities_are_reported() {
    let translation = vc_layout::translate(GDC).expect("the gdc layout translates");
    let warned: Vec<&str> = translation
        .report
        .warned
        .iter()
        .map(|(path, _)| path.as_str())
        .collect();
    // The gdc document exercises these unsupported capabilities; each
    // must be reported by its member path (the classifier records the
    // leaf it classified) so the operator knows what the translated
    // deployment runs without.
    for path in [
        "verifier.preferred_vp_formats.ldp_vc.cryptosuite_values",
        "verifier.preferred_vp_formats.ldp_vc.proof_type_values",
        "verifier.digital_credentials.use_jar",
        "verifier.trust.wallet_attestation.enabled",
        "common.ha.enable",
        "common.ha.cache_database_name",
        "common.tracing.enable",
        "common.tracing.addr",
        "common.branding.logo_path",
        "common.branding.favicon_path",
        "verifier.inbound.openid4vp.presentation_requests_dir",
    ] {
        assert!(
            warned.contains(&path),
            "the report must warn about {path} (warned: {warned:?})"
        );
    }
}

#[test]
fn the_gdc_layouts_mapped_members_reach_the_emitted_config() {
    let translation = vc_layout::translate(GDC).expect("the gdc layout translates");
    let doc: toml::Table =
        toml::from_str(&translation.toml).expect("the emitted proxy.toml parses as TOML");

    // The identity and the session.
    assert_eq!(
        doc.get("base_url").and_then(|v| v.as_str()),
        Some("https://sirosid-gdc-vc-verifier.fly.dev")
    );
    assert_eq!(
        doc.get("state_encryption_key").and_then(|v| v.as_str()),
        Some("${SIROS_VERIFIER_STATE_KEY}")
    );
    assert_eq!(
        doc.get("state_cookie_max_age").and_then(|v| v.as_integer()),
        Some(900),
        "the vc session_duration becomes the state cookie's max age"
    );

    // The frontends: the ui with its presets, and the OP with the vc
    // layout's TTLs.
    let frontends = doc
        .get("frontend")
        .and_then(|v| v.as_array())
        .expect("the emitted config carries frontends");
    assert_eq!(frontends.len(), 2, "the ui and the oidc frontends");
    let oidc = frontends
        .iter()
        .find(|f| f.get("type").and_then(|v| v.as_str()) == Some("oidc"))
        .expect("the oidc frontend");
    let oidc_config = oidc.get("config").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        oidc_config.get("code_ttl").and_then(|v| v.as_integer()),
        Some(600),
        "the vc code_duration becomes the OP's code_ttl"
    );
    assert_eq!(
        oidc_config
            .get("refresh_token_ttl")
            .and_then(|v| v.as_integer()),
        Some(86400)
    );
    let clients = oidc_config
        .get("clients")
        .and_then(|v| v.as_array())
        .expect("the vc clients map becomes the OP's roster");
    assert_eq!(
        clients.len(),
        1,
        "the gdc layout registers one wallet-frontend RP"
    );
    let client = clients[0].as_table().unwrap();
    assert_eq!(
        client.get("client_id").and_then(|v| v.as_str()),
        Some("https://sirosid-gdc-wallet-frontend.fly.dev/id/default/")
    );
    assert_eq!(
        client
            .get("token_endpoint_auth_method")
            .and_then(|v| v.as_str()),
        Some("none"),
        "the vc `type: public` client is a PKCE-only (auth method none) client"
    );

    // The backend: the key paths carry over verbatim (the same volume
    // mounts serve the translated deployment), the mongo URI verbatim,
    // the PDP endpoint, the zkp block with the vc circuits.
    let backends = doc
        .get("backend")
        .and_then(|v| v.as_array())
        .expect("the emitted config carries the openid4vp backend");
    let backend = backends[0].as_table().unwrap();
    let bconfig = backend.get("config").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        bconfig
            .get("request_signing_key_path")
            .and_then(|v| v.as_str()),
        Some("/pki/signing_ec_private.pem")
    );
    assert_eq!(
        bconfig
            .get("request_certificate_chain_path")
            .and_then(|v| v.as_str()),
        Some("/pki/signing_ec_chain.pem")
    );
    assert_eq!(
        bconfig.get("pdp_endpoint").and_then(|v| v.as_str()),
        Some("http://sirosid-gdc-pdp.internal:8080")
    );
    assert_eq!(
        bconfig.get("request_ttl_secs").and_then(|v| v.as_integer()),
        Some(300),
        "the vc presentation_timeout becomes request_ttl_secs"
    );
    let storage = bconfig.get("storage").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        storage.get("backend").and_then(|v| v.as_str()),
        Some("mongodb")
    );
    assert!(storage
        .get("uri")
        .and_then(|v| v.as_str())
        .unwrap()
        .starts_with("mongodb://"));

    // The zkp block: both gdc circuits (the longfellow and the vega
    // one), the pinned artifact hash, the verifier id.
    let zkp = bconfig.get("zkp").and_then(|v| v.as_table()).unwrap();
    let circuits = zkp.get("circuits").and_then(|v| v.as_table()).unwrap();
    let allow = circuits.get("allow").and_then(|v| v.as_array()).unwrap();
    assert_eq!(allow.len(), 2, "the gdc nym_auth allowlist's two circuits");
    let first = allow[0].as_table().unwrap();
    assert_eq!(
        first.get("artifact_sha256").and_then(|v| v.as_str()),
        Some("92dd42fdf99673249eec33c7d07850bd9da66fbdab01ef26391e04c8341c1b7f"),
        "the pinned circuit hash carries verbatim"
    );
    assert_eq!(
        zkp.get("verifier_id").and_then(|v| v.as_str()),
        Some("x509_san_dns:sirosid-gdc-vc-verifier.fly.dev")
    );

    // The presets: the gdc zk presets ride the ui frontend, the
    // ldp_vc-only preset is dropped with the warning (asserted in the
    // known-unsupported test's terms by the translation succeeding with
    // the reported warned list).
    let ui = frontends
        .iter()
        .find(|f| f.get("type").and_then(|v| v.as_str()) == Some("ui"))
        .expect("the ui frontend");
    let ui_config = ui.get("config").and_then(|v| v.as_table()).unwrap();
    let presets = ui_config
        .get("presets")
        .and_then(|v| v.as_array())
        .expect("the presets translate onto the ui frontend");
    assert_eq!(
        presets.len(),
        4,
        "the gdc layout's four supported presets (the ldp_vc-only Accredify one is dropped with the warning)"
    );
    let labels: Vec<&str> = presets
        .iter()
        .map(|p| p.get("label").and_then(|v| v.as_str()).unwrap())
        .collect();
    for label in [
        "nym_auth_pseudonym",
        "nym_auth_pseudonym_age",
        "Age Over 18 - ZK Proof (Vega)",
        "PID (mdoc) - ZK Proof (Vega)",
    ] {
        assert!(
            labels.contains(&label),
            "the preset {label} must survive the translation (labels: {labels:?})"
        );
    }
}

#[test]
fn an_unknown_member_refuses_the_translation() {
    // Neither the adapter's mapped set nor the vc model's known members:
    // a new upstream feature (or a typo) must fail loudly, not vanish
    // from a translated deployment.
    let source = format!("{GDC}\n  totally_new_feature: true\n");
    let err = match vc_layout::translate(&source) {
        Ok(_) => panic!("an unknown member must refuse the translation"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("totally_new_feature"),
        "the refusal names the unknown member: {err:#}"
    );
}

#[test]
fn a_typo_refuses_the_translation() {
    let source = GDC.replace("presentation_timeout:", "presentation_timout:");
    let err = match vc_layout::translate(&source) {
        Ok(_) => panic!("a typo must refuse the translation"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("presentation_timout"),
        "the refusal names the typo: {err:#}"
    );
}
/// The translated config boots the REAL service: the `--from-vc-layout`
/// mode reads the vc layout, translates, and starts — the drop-in
/// replacement's acceptance. The fixture is the gdc shape with local
/// keys and memory storage.
#[tokio::test]
async fn the_translated_layout_boots_the_service_healthy() {
    use std::process::Stdio;
    use tokio::process::Command;

    let dir = std::env::temp_dir().join(format!("siros-verifier-vc-boot-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A real key pair for the request/OP signing (the startup suite's
    // rcgen pattern).
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["verifier.example".to_string()])
        .unwrap()
        .self_signed(&kp)
        .unwrap();
    std::fs::write(dir.join("key.pem"), kp.serialize_pem()).unwrap();
    std::fs::write(dir.join("chain.pem"), cert.pem()).unwrap();
    let layout = include_str!("../testdata/vc-layout/boot.yaml")
        .replace(
            "KEY_PLACEHOLDER",
            &dir.join("key.pem").display().to_string(),
        )
        .replace(
            "KEYCHAIN_PLACEHOLDER",
            &dir.join("chain.pem").display().to_string(),
        );
    let layout_path = dir.join("config.yaml");
    std::fs::write(&layout_path, layout).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Command::new(env!("CARGO_BIN_EXE_siros-verifier-service"))
        .arg("--from-vc-layout")
        .arg(&layout_path)
        .env("TUNNELBANA_BIND", address.to_string())
        .env(
            "SIROS_VERIFIER_STATE_KEY",
            "a-32-byte-or-longer-test-secret!!",
        )
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let healthy = tokio::time::timeout(std::time::Duration::from_secs(60), async {
        loop {
            // A child that exited cannot have answered /health: collect
            // its stderr on the failure path only.
            if let Ok(Some(status)) = child.try_wait() {
                let _ = child.kill().await;
                panic!("the translated boot exited: {status}");
            }
            if let Ok(response) = client.get(format!("http://{address}/health")).send().await {
                if response.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
    })
    .await;
    assert!(
        healthy.is_ok(),
        "the service booted from the vc layout and answered /health"
    );
    let _ = child.kill().await;
    let _ = std::fs::remove_dir_all(&dir);
}
