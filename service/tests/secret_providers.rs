//! The concrete secret providers and the default client roster: the
//! operational implementations of the core's traits, as the boot uses
//! them. Every refusal names the entry and the source involved.

use serde_json::json;
use siros_verifier_core::config::{ClientRegistrationProvider, SecretProvider, SecretSource};
use siros_verifier_service::config::{
    ConfigClientRegistration, EnvVarSecretProvider, FileSecretProvider, PlatformSecretProvider,
};

/// A fake provider for deterministic roster tests: hands out a
/// canned value, refuses everything else.
struct FakeProvider {
    env: Vec<(&'static str, &'static str)>,
}

impl SecretProvider for FakeProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        match source {
            SecretSource::Env(name) => self
                .env
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.to_string())
                .ok_or_else(|| {
                    siros_verifier_core::Error::Policy(format!(
                        "secret provider: env var {name} is not set"
                    ))
                }),
            SecretSource::File(path) => Err(siros_verifier_core::Error::Policy(format!(
                "secret provider: env vars only, not the secret file {path}"
            ))),
        }
    }
}

fn provider() -> std::sync::Arc<dyn SecretProvider> {
    std::sync::Arc::new(FakeProvider {
        env: vec![("VC_TEST_SECRET", "s3cret")],
    })
}

// ---- the roster ----------------------------------------------------------------

#[test]
fn a_roster_entry_with_an_env_reference_resolves_and_strips_it() {
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "client_secret_env": "VC_TEST_SECRET",
            "redirect_uris": ["https://rp.example.org/callback"],
        })],
        provider(),
    );
    let clients = reg.clients().expect("resolution succeeds");
    assert_eq!(clients.len(), 1);
    assert_eq!(clients[0]["client_secret"], "s3cret");
    assert!(clients[0].get("client_secret_env").is_none());
    assert_eq!(
        clients[0]["redirect_uris"][0],
        "https://rp.example.org/callback"
    );
}

#[test]
fn the_full_client_shape_survives_the_env_resolution() {
    // The tunnelbana OIDC frontend's Client fields (redirect_uris,
    // response_types, grant_types, token_endpoint_auth_method, ...)
    // must survive the `_env` roundtrip untouched — the provider
    // resolves the credential and strips only the `_env` field; the
    // strict downstream parser sees the same entry it would have
    // seen with an inline secret.
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "client_secret_env": "VC_TEST_SECRET",
            "redirect_uris": ["https://rp.example.org/callback"],
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
            "client_name": "Example RP",
        })],
        provider(),
    );
    let clients = reg.clients().expect("resolution succeeds");
    assert_eq!(clients[0]["client_secret"], "s3cret");
    assert_eq!(
        clients[0]["redirect_uris"][0],
        "https://rp.example.org/callback"
    );
    assert_eq!(clients[0]["response_types"][0], "code");
    assert_eq!(clients[0]["grant_types"][1], "refresh_token");
    assert_eq!(
        clients[0]["token_endpoint_auth_method"],
        "client_secret_basic"
    );
    assert_eq!(clients[0]["client_name"], "Example RP");
    assert!(clients[0].get("client_secret_env").is_none());
}

#[test]
fn the_roster_is_reachable_through_the_core_trait() {
    // The core's ClientRegistrationProvider is the interface; the
    // service's config roster is one implementation of it.
    let reg = ConfigClientRegistration::new(
        vec![json!({"client_id": "rp", "client_secret": "x"})],
        provider(),
    );
    let clients = ClientRegistrationProvider::clients(&reg).expect("the trait resolves the roster");
    assert_eq!(clients[0]["client_id"], "rp");
}

#[test]
fn an_inline_secret_passes_through_untouched() {
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "client_secret": "inline-value",
        })],
        provider(),
    );
    let clients = reg.clients().expect("resolution succeeds");
    assert_eq!(clients[0]["client_secret"], "inline-value");
}

#[test]
fn an_entry_without_a_secret_passes_through() {
    // A `none` or `private_key_jwt` client carries no client_secret at all.
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "token_endpoint_auth_method": "private_key_jwt",
        })],
        provider(),
    );
    let clients = reg.clients().expect("resolution succeeds");
    assert!(clients[0].get("client_secret").is_none());
}

#[test]
fn both_an_inline_secret_and_an_env_reference_are_refused() {
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "client_secret": "inline-value",
            "client_secret_env": "VC_TEST_SECRET",
        })],
        provider(),
    );
    let err = match reg.clients() {
        Ok(_) => panic!("two sources must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("client rp"),
        "the refusal must name the client: {err}"
    );
}

#[test]
fn a_missing_env_variable_is_refused_with_the_client_and_variable_named() {
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "client_secret_env": "VC_NEVER_SET",
        })],
        provider(),
    );
    let err = match reg.clients() {
        Ok(_) => panic!("a missing variable must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("client rp") && err.to_string().contains("VC_NEVER_SET"),
        "the refusal must name the client and the variable: {err}"
    );
}

#[test]
fn an_empty_env_variable_is_refused() {
    let reg = ConfigClientRegistration::new(
        vec![json!({
            "client_id": "rp",
            "client_secret_env": "VC_EMPTY",
        })],
        std::sync::Arc::new(FakeProvider {
            env: vec![("VC_EMPTY", "")],
        }),
    );
    let err = match reg.clients() {
        Ok(_) => panic!("an empty variable must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("client rp"),
        "the refusal must name the client: {err}"
    );
}

#[test]
fn a_duplicate_client_id_across_the_roster_is_refused() {
    let reg = ConfigClientRegistration::new(
        vec![
            json!({ "client_id": "rp", "client_secret": "a" }),
            json!({ "client_id": "rp", "client_secret": "b" }),
        ],
        provider(),
    );
    let err = match reg.clients() {
        Ok(_) => panic!("a duplicate id must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("duplicate client_id 'rp'"),
        "the refusal must name the duplicate: {err}"
    );
}

#[test]
fn a_non_object_roster_entry_is_refused() {
    let reg = ConfigClientRegistration::new(vec![json!("just a string")], provider());
    let err = match reg.clients() {
        Ok(_) => panic!("a non-object entry must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("not a JSON object"),
        "the refusal must name the shape: {err}"
    );
}

// ---- the concrete providers ------------------------------------------------------

#[test]
fn the_env_provider_refuses_a_missing_variable() {
    let err = match EnvVarSecretProvider
        .resolve(&SecretSource::Env("VC_CONFIG_TEST_DEFINITELY_UNSET".into()))
    {
        Ok(_) => panic!("a missing variable must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("VC_CONFIG_TEST_DEFINITELY_UNSET"),
        "the refusal must name the variable: {err}"
    );
}

#[test]
fn the_env_provider_refuses_a_file_source() {
    let err = match EnvVarSecretProvider.resolve(&SecretSource::File("/secrets/x".into())) {
        Ok(_) => panic!("the env provider must refuse file sources"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("env vars only"),
        "the refusal must name the limitation: {err}"
    );
}

#[test]
fn the_file_provider_refuses_an_env_source() {
    let err = match FileSecretProvider::new("/secrets").resolve(&SecretSource::Env("VC_X".into())) {
        Ok(_) => panic!("the file provider must refuse env sources"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("secret files only"),
        "the refusal must name the limitation: {err}"
    );
}

#[test]
fn the_file_provider_resolves_relative_paths_against_its_base() {
    let tmp = std::env::temp_dir().join("svc-test-file-provider-relative");
    std::fs::create_dir_all(tmp.join("sub")).expect("mkdir");
    std::fs::write(tmp.join("sub/token"), "nested").expect("write");
    let got = FileSecretProvider::new(&tmp)
        .resolve(&SecretSource::File("sub/token".into()))
        .expect("resolution succeeds");
    assert_eq!(got, "nested");
}

#[test]
fn the_file_provider_refuses_a_missing_file() {
    let tmp = std::env::temp_dir().join("svc-test-file-provider-missing");
    std::fs::create_dir_all(&tmp).expect("mkdir");
    let err = match FileSecretProvider::new(&tmp).resolve(&SecretSource::File("gone".into())) {
        Ok(_) => panic!("a missing file must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("gone"),
        "the refusal must name the file: {err}"
    );
}

#[test]
fn the_file_provider_refuses_an_empty_file() {
    // The fail-fast contract: an empty file is a mounted key that was
    // never filled in — as useless as a missing one.
    let tmp = std::env::temp_dir().join("svc-test-file-provider-empty");
    std::fs::create_dir_all(&tmp).expect("mkdir");
    std::fs::write(tmp.join("token"), "").expect("write");
    let err = match FileSecretProvider::new(&tmp).resolve(&SecretSource::File("token".into())) {
        Ok(_) => panic!("an empty file must be refused"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("token"),
        "the refusal must name the file: {err}"
    );
}

#[test]
fn the_platform_provider_serves_both_channels() {
    let tmp = std::env::temp_dir().join("svc-test-platform-provider");
    std::fs::create_dir_all(&tmp).expect("mkdir");
    std::fs::write(tmp.join("token"), "from-a-file").expect("write");
    // The env channel needs a real variable: one process-global set,
    // a name unique to this test.
    std::env::set_var("VC_CONFIG_PLATFORM_TEST_ENV", "from-an-env-var");
    let provider = PlatformSecretProvider::new(&tmp);
    let got_env = provider
        .resolve(&SecretSource::Env("VC_CONFIG_PLATFORM_TEST_ENV".into()))
        .expect("the env channel resolves");
    assert_eq!(got_env, "from-an-env-var");
    let got_file = provider
        .resolve(&SecretSource::File("token".into()))
        .expect("the file channel resolves");
    assert_eq!(got_file, "from-a-file");
    std::env::remove_var("VC_CONFIG_PLATFORM_TEST_ENV");
}
