//! The deployment configuration refuses unknown fields: a typo in the
//! configuration file is a startup error, never a silently ignored setting.

use serde_json::json;
use siros_verifier_service::config::DeploymentConfig;

#[test]
fn unknown_deployment_fields_are_refused() {
    let valid = json!({
        "request_signing_key_path": "/k",
        "request_certificate_chain_path": "/c",
        "pdp_endpoint": "https://pdp.example/evaluation",
        "storage": {"backend": "memory"},
        "dcql": {"credentials": []},
        "attribute_map": {},
        "subject_pointer": "/sub",
        "role": "pid-provider",
    });
    // Positive control: the document without the extra field is a valid
    // deployment configuration, so the refusal below is because of the
    // unknown field and nothing else.
    serde_json::from_value::<DeploymentConfig>(valid.clone())
        .expect("the fixture without the unknown field is valid");
    let mut refused = valid;
    refused["unexpected"] = json!(true);
    let error = serde_json::from_value::<DeploymentConfig>(refused)
        .expect_err("an unknown field is a startup error");
    assert!(
        error.to_string().contains("unexpected"),
        "{error}: the refusal must name the unknown field"
    );
}

#[test]
fn the_secret_reference_and_rotation_fields_parse() {
    // The `_env`/`_file` references and the previous request-signing
    // pair are deployment fields like any other: present in the
    // document, absent by default. The refusals they can cause are
    // covered by the provider tests; this pins the shapes themselves.
    let parsed: DeploymentConfig = serde_json::from_value(json!({
        "request_signing_key_path": "/k",
        "request_certificate_chain_path": "/c",
        "pdp_endpoint": "https://pdp.example/evaluation",
        "storage": {
            "backend": "mongodb",
            "uri_env": "VC_MONGO_URI",
            "database": "siros_verifier",
        },
        "pdp_bearer_token_file": "secrets/pdp-token",
        "previous_request_signing_key_path": "/old-k",
        "previous_request_certificate_chain_path": "/old-c",
        "dcql": {"credentials": []},
        "attribute_map": {},
        "subject_pointer": "/sub",
        "role": "pid-provider",
    }))
    .expect("the reference and rotation fields parse");
    assert_eq!(
        parsed.pdp_bearer_token_file.as_deref(),
        Some("secrets/pdp-token")
    );
    assert_eq!(parsed.storage.uri_env.as_deref(), Some("VC_MONGO_URI"));
    assert_eq!(
        parsed.previous_request_signing_key_path.as_deref(),
        Some("/old-k")
    );
}
