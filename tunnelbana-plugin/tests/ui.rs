//! The UI page's public surface: the stylesheet the demo frontend renders.
//!
//! The claim picker's layout rules live in `ui::page`'s inline stylesheet —
//! a regression there renders the #63 checkbox fieldset as an inline run
//! instead of a vertical list (found live in the WRPAC drill). These tests
//! pin the layout where the picker's operator sees it: the label boxes as
//! block-level flex rows, one per line.

use siros_verifier_core_tunnelbana::ui;

/// The label layout rule must render one checkbox label per line: a
/// block-level flex row on the `claim-group label` selector, with the
/// checkbox itself flexed to its natural width at the left of the row.
/// `display:inline` (or `inline-flex`) restores the reported bug — a
/// linear, unsorted run on one line — and must fail this check.
#[test]
fn claim_labels_lay_out_vertically() {
    let html = ui::page("test", "");
    let Some(css) = extract_style(&html) else {
        panic!("the page carries no stylesheet");
    };
    // The label boxes are block-level flex rows: `display:inline` (or
    // `inline-flex`, which wraps the same run) restores the one-line bug.
    let rule = style_rule(&css, ".claim-group label")
        .unwrap_or_else(|| panic!("no .claim-group label rule in the stylesheet"));
    assert!(
        rule.starts_with("display:flex;"),
        "the label boxes must be flex rows, not an inline run: {rule}"
    );
    // The checkbox keeps its own width at the row's left.
    let box_rule = style_rule(&css, ".claim-group input[type=\"checkbox\"]")
        .unwrap_or_else(|| panic!("no checkbox input rule in the stylesheet"));
    assert!(
        box_rule.contains("flex:none"),
        "the checkbox must not stretch with the row: {box_rule}"
    );
}

/// The stylesheet is the page's first <style> element.
fn extract_style(html: &str) -> Option<String> {
    let start = html.find("<style>")? + "<style>".len();
    let end = html[start..].find("</style>")? + start;
    Some(html[start..end].to_owned())
}

/// A CSS rule's declarations, joined as written (whitespace-normalized).
/// The selector matches when its own whitespace-separated tokens are the
/// rule selector's trailing tokens (`.claim-group label` matches the rule
/// `.claim-group label { … }` however the source breaks its lines).
fn style_rule(css: &str, selector: &str) -> Option<String> {
    let want: Vec<&str> = selector.split_whitespace().collect();
    for raw in css.split('}') {
        let Some((sel, declarations)) = raw.split_once('{') else {
            continue;
        };
        let have: Vec<&str> = sel.split_whitespace().collect();
        if have.len() >= want.len() && have[have.len() - want.len()..] == want[..] {
            return Some(
                declarations
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
    }
    None
}
