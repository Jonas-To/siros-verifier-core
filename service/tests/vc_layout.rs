//! The VC-layout adapter: the gdc deployment's actual vc-stack verifier
//! configuration is the acceptance fixture. The translation must place
//! every member of that document in a taxonomy bucket (mapped or
//! known-unsupported — never silently dropped), and the emitted
//! proxy.toml must be a real, bootable service configuration.

/// The gdc deployment's rendered vc-verifier.yaml, with ONE redaction:
/// the mongo URI's embedded password (a live credential has no business
/// committed in this repository; the URI's shape is what the adapter
/// reads).
const GDC: &str = include_str!("../testdata/vc-layout/gdc.yaml");

/// Translate the gdc fixture the way the boot does: the source's own
/// directory (its paths are absolute — the source dir is inert), the
/// default policy switches.
fn translate_gdc() -> siros_verifier_service::vc_layout::Translation {
    let options = full_gdc_options();
    let dir = std::path::Path::new("/etc/vc");
    siros_verifier_service::vc_layout::translate(GDC, dir, &options)
        .unwrap_or_else(|e| panic!("the gdc layout translates: {e:#}"))
}

/// Translate a source with a policy switch.
fn translate_gdc_with(
    options: &siros_verifier_service::vc_layout::TranslateOptions,
) -> Result<siros_verifier_service::vc_layout::Translation, anyhow::Error> {
    let dir = std::path::Path::new("/etc/vc");
    siros_verifier_service::vc_layout::translate(GDC, dir, options)
}

/// The gdc deployment's full policy posture: HTTP to the PDP on fly's
/// private network (the explicit opt-in) and the PAN as the OP's
/// subject identifier.
fn full_gdc_options() -> siros_verifier_service::vc_layout::TranslateOptions {
    siros_verifier_service::vc_layout::TranslateOptions {
        allow_insecure_pdp: true,
        subject_pointer: Some("/personal_administrative_number".into()),
    }
}

#[test]
fn the_gdc_layout_translates_with_no_unknown_members() {
    let translation = translate_gdc();
    // The taxonomy walk found no unknown members (translate would have
    // refused), and the report records both mapped and warned paths.
    assert!(!translation.report.mapped.is_empty());
    assert!(!translation.report.warned.is_empty());
}

#[test]
fn the_gdc_layouts_known_unsupported_capabilities_are_reported() {
    let translation = translate_gdc();
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
    let translation = translate_gdc();
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

    // The presets: the gdc nym_auth presets ride the ui frontend; the
    // ldp_vc-only Accredify preset AND the two Vega mso_mdoc_zk presets
    // are dropped with the warnings (the vc profiles this service does
    // not speak).
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
        2,
        "the two nym_auth presets survive; the ldp_vc and the Vega mso_mdoc_zk presets are dropped"
    );
    let labels: Vec<&str> = presets
        .iter()
        .map(|p| p.get("label").and_then(|v| v.as_str()).unwrap())
        .collect();
    for label in ["nym_auth_pseudonym", "nym_auth_pseudonym_age"] {
        assert!(
            labels.contains(&label),
            "the preset {label} must survive the translation (labels: {labels:?})"
        );
    }

    // The zkp block: the SECOND distinct query rides the profiles list
    // (a preset is served only when its exact query is configured).
    let zkp = bconfig.get("zkp").and_then(|v| v.as_table()).unwrap();
    let profiles = zkp
        .get("profiles")
        .and_then(|v| v.as_array())
        .expect("the age-check preset's distinct query rides the profiles");
    assert_eq!(profiles.len(), 1, "one distinct non-fallback query");
    let profile = profiles[0].as_table().unwrap();
    assert_eq!(
        profile.get("subject_handle").and_then(|v| v.as_str()),
        Some("nym"),
        "the profile's subject handle is the pseudonym function's return"
    );
}

#[test]
fn a_plain_http_pdp_refuses_without_the_explicit_opt_in() {
    // The transport policy is not silently relaxed: the gdc layout's
    // internal-HTTP PDP needs the explicit opt-in, and with it the
    // emitted config states allow_insecure_http as loudly as the
    // native config would.
    let mut options = full_gdc_options();
    options.allow_insecure_pdp = false;
    let err = match translate_gdc_with(&options) {
        Ok(_) => panic!("the gdc PDP is plain HTTP on a non-loopback address — refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("--allow-insecure-pdp"),
        "the refusal names the opt-in: {err:#}"
    );
    let allowed = full_gdc_options();
    let translation = translate_gdc_with(&allowed).expect("the opt-in permits it");
    let doc: toml::Table =
        toml::from_str(&translation.toml).expect("the emitted proxy.toml parses as TOML");
    let backend = doc.get("backend").and_then(|v| v.as_array()).unwrap()[0]
        .as_table()
        .unwrap();
    let bconfig = backend.get("config").and_then(|v| v.as_table()).unwrap();
    assert_eq!(
        bconfig.get("allow_insecure_http").and_then(|v| v.as_bool()),
        Some(true),
        "the opt-in emits the explicit escape hatch"
    );
}

#[test]
fn a_typo_under_a_dynamic_key_refuses_the_translation() {
    // The enumerated taxonomy under dynamic keys: `cliams` inside a
    // preset matches no member pattern and refuses, rather than passing
    // as a mapped subtree and silently dropping the claims.
    let source = GDC.replacen("          claims:\n", "          cliams:\n", 1);
    let options = full_gdc_options();
    let err = match siros_verifier_service::vc_layout::translate(
        &source,
        std::path::Path::new("/etc/vc"),
        &options,
    ) {
        Ok(_) => panic!("a typo under a dynamic key must refuse"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("cliams"),
        "the refusal names the typo: {err:#}"
    );
}

#[test]
fn a_mixed_preset_refuses_the_translation() {
    // A preset mixing a supported and an unsupported credential would
    // silently lose a requirement — the reduced query is not what the
    // operator configured. Refuse it.
    let source = GDC.replacen(
        "  nym_auth_pseudonym_age:\n",
        "  nym_auth_pseudonym_age:\n    credentials:\n      pid_eudi:\n        format: dc+sd-jwt\n      accredify_individual_id:\n        format: ldp_vc\n",
        1,
    );
    let options = full_gdc_options();
    let err = match siros_verifier_service::vc_layout::translate(
        &source,
        std::path::Path::new("/etc/vc"),
        &options,
    ) {
        Ok(_) => panic!("a mixed preset must refuse"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("nym_auth_pseudonym_age")
            && err.to_string().contains("accredify_individual_id"),
        "the refusal names the preset and the unsupported credential: {err:#}"
    );
}

#[test]
fn an_unknown_member_refuses_the_translation() {
    // Neither the adapter's mapped set nor the vc model's known members:
    // a new upstream feature (or a typo) must fail loudly, not vanish
    // from a translated deployment.
    let source = format!("{GDC}\n  totally_new_feature: true\n");
    let options = siros_verifier_service::vc_layout::TranslateOptions::default();
    let err = match siros_verifier_service::vc_layout::translate(
        &source,
        std::path::Path::new("/etc/vc"),
        &options,
    ) {
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
    let options = siros_verifier_service::vc_layout::TranslateOptions::default();
    let err = match siros_verifier_service::vc_layout::translate(
        &source,
        std::path::Path::new("/etc/vc"),
        &options,
    ) {
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
        // The fixture carries an OP: the explicit subject mapping the
        // translation demands (the given_name claim is the fixture's
        // unique-enough identifier).
        .arg("--subject-pointer")
        .arg("/given_name")
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

#[test]
fn the_fallback_dcql_requests_the_subject_identifier() {
    // The OP's OIDC logins ride the fallback — its FIRST query must
    // request the identifier the subject derives from, or a wallet
    // omitting it passes verification and fails at the subject claim.
    let translation = translate_gdc();
    let doc: toml::Table =
        toml::from_str(&translation.toml).expect("the emitted proxy.toml parses as TOML");
    let backend = doc.get("backend").and_then(|v| v.as_array()).unwrap()[0]
        .as_table()
        .unwrap();
    let bconfig = backend.get("config").and_then(|v| v.as_table()).unwrap();
    let credentials = bconfig
        .get("dcql")
        .and_then(|v| v.as_table())
        .unwrap()
        .get("credentials")
        .and_then(|v| v.as_array())
        .unwrap();
    let first = credentials[0].as_table().unwrap();
    let claims = first
        .get("claims")
        .and_then(|v| v.as_array())
        .expect("the first fallback query carries claims");
    let paths: Vec<String> = claims
        .iter()
        .filter_map(|c| {
            let segments: Vec<String> = c
                .as_table()?
                .get("path")?
                .as_array()?
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect();
            Some(segments.join("."))
        })
        .collect();
    assert!(
        paths.contains(&"personal_administrative_number".to_string()),
        "the fallback requests the configured identifier claim (paths: {paths:?})"
    );
}
