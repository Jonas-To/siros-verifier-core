//! The per-field secret-reference pattern: a scalar secret-bearing field
//! takes at most one of an inline value, an `_env` reference and a `_file`
//! reference; resolution is the provider's, and the refusals name the
//! field and the source.

use siros_verifier_core::config::{resolve_secret_field, SecretProvider, SecretSource};
use siros_verifier_core::Error;

/// A fake provider for deterministic tests: hands out canned values
/// for the sources it knows, refuses everything else.
struct FakeProvider {
    env: Vec<(&'static str, &'static str)>,
    files: Vec<(&'static str, &'static str)>,
}

impl SecretProvider for FakeProvider {
    fn resolve(&self, source: &SecretSource) -> siros_verifier_core::Result<String> {
        let (known, name) = match source {
            SecretSource::Env(name) => (&self.env, name),
            SecretSource::File(path) => (&self.files, path),
        };
        known
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.to_string())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                Error::Policy(format!(
                    "secret provider: {}: not set or empty",
                    source.describe()
                ))
            })
    }
}

fn provider() -> FakeProvider {
    FakeProvider {
        env: vec![("VC_TEST_SECRET", "s3cret")],
        files: vec![("secrets/pdp-token", "file-secret")],
    }
}

#[test]
fn a_field_resolves_its_env_reference() {
    let got = resolve_secret_field(
        "pdp_bearer_token",
        None,
        Some("VC_TEST_SECRET"),
        None,
        &provider(),
    )
    .expect("resolution succeeds");
    assert_eq!(got.as_deref(), Some("s3cret"));
}

#[test]
fn a_field_resolves_its_file_reference() {
    let got = resolve_secret_field(
        "pdp_bearer_token",
        None,
        None,
        Some("secrets/pdp-token"),
        &provider(),
    )
    .expect("resolution succeeds");
    assert_eq!(got.as_deref(), Some("file-secret"));
}

#[test]
fn a_field_with_an_inline_value_and_a_reference_is_refused() {
    let err = resolve_secret_field(
        "pdp_bearer_token",
        Some("inline"),
        Some("VC_TEST_SECRET"),
        None,
        &provider(),
    )
    .expect_err("two sources must be refused");
    assert!(
        err.to_string().contains("pdp_bearer_token"),
        "the refusal must name the field: {err}"
    );
}

#[test]
fn a_field_with_both_env_and_file_references_is_refused() {
    let err = resolve_secret_field(
        "pdp_bearer_token",
        None,
        Some("VC_TEST_SECRET"),
        Some("secrets/pdp-token"),
        &provider(),
    )
    .expect_err("two sources must be refused");
    assert!(
        err.to_string().contains("pdp_bearer_token"),
        "the refusal must name the field: {err}"
    );
}

#[test]
fn a_field_with_no_source_is_none() {
    let got = resolve_secret_field("pdp_bearer_token", None, None, None, &provider())
        .expect("no source is not an error");
    assert_eq!(got, None);
}

#[test]
fn a_missing_source_is_refused_with_the_field_and_source_named() {
    let err = resolve_secret_field(
        "pdp_bearer_token",
        None,
        Some("VC_NEVER_SET"),
        None,
        &provider(),
    )
    .expect_err("a missing source must be refused");
    assert!(
        err.to_string().contains("pdp_bearer_token") && err.to_string().contains("VC_NEVER_SET"),
        "the refusal must name the field and the source: {err}"
    );
}

#[test]
fn an_empty_source_is_refused() {
    let err = resolve_secret_field(
        "pdp_bearer_token",
        None,
        Some("VC_EMPTY"),
        None,
        &FakeProvider {
            env: vec![("VC_EMPTY", "")],
            files: vec![],
        },
    )
    .expect_err("an empty source must be refused");
    assert!(
        err.to_string().contains("pdp_bearer_token"),
        "the refusal must name the field: {err}"
    );
}

#[test]
fn the_source_description_names_the_channel() {
    assert_eq!(SecretSource::Env("VC_X".into()).describe(), "env var VC_X");
    assert_eq!(
        SecretSource::File("/secrets/x".into()).describe(),
        "secret file /secrets/x"
    );
}
