//! A local connector Guard has not been set up for on this device.
//!
//! A command review that is due only to Guard not recognising the local CLI
//! it launches is a setup decision, not a per-action one. Such reviews are
//! still queued, but under one `connector:<identity_hash>:<action>` group per
//! connector, so the Inbox can show one setup card over every call waiting on
//! it. Identical actions share a group id and merge (`dedupe_count`); distinct
//! actions keep their own rows, so grouping reduces cards, not evidence.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::approval_queue_identity_op::normalize_command_identity;

/// The reason code an agent and the Inbox see for a connector setup review.
pub(crate) const CONNECTOR_SETUP_REQUIRED: &str = "connector_setup_required";

/// Review reason codes that mean only "Guard does not recognise this command".
/// Any other code carries a risk signal and keeps its per-action review.
pub(crate) const NON_RECOGNITION_REASON_CODES: [&str; 1] = ["native_command_review_required"];

/// Hex digits of the action digest in a connector group id.
const ACTION_DIGEST_HEX: usize = 16;

/// Whether `reason_code` is a review due only to non-recognition.
pub(crate) fn is_non_recognition(reason_code: Option<&str>) -> bool {
    reason_code.is_some_and(|code| NON_RECOGNITION_REASON_CODES.contains(&code))
}

/// `connector:<identity_hash>:<action digest>` for one command of a connector.
pub(crate) fn queue_group_id(identity_hash: &str, command: &str) -> String {
    let action = hex::encode(Sha256::digest(
        normalize_command_identity(command).as_bytes(),
    ));
    format!("connector:{identity_hash}:{}", &action[..ACTION_DIGEST_HEX])
}

/// Whether `group` is a bare `connector:<identity_hash>` marker, which the
/// queue completes with the row's own action digest.
pub(crate) fn is_connector_marker(group: &str) -> bool {
    group.strip_prefix("connector:").is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

/// `<marker>:<action digest>` for a row whose default group id is `default_group`.
pub(crate) fn action_group_id(marker: &str, default_group: &str) -> String {
    let action = hex::encode(Sha256::digest(default_group.as_bytes()));
    format!("{marker}:{}", &action[..ACTION_DIGEST_HEX])
}

/// The connector a hook review is waiting on, as `LocalCliHook` returns it.
pub(crate) fn payload(
    cli_id: &str,
    identity_hash: &str,
    name: &str,
    kind: &str,
    command: &str,
) -> Value {
    let surface = if kind == "script" {
        "package-scripts"
    } else {
        "cli"
    };
    json!({
        "cli_id": cli_id,
        "identity_hash": identity_hash,
        "name": name,
        "surface": surface,
        "queue_group_id": queue_group_id(identity_hash, command),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_actions_share_a_group_and_distinct_actions_do_not() {
        let hash = "a".repeat(64);
        let first = queue_group_id(&hash, "lanectl status");
        assert_eq!(first, queue_group_id(&hash, "lanectl   status"));
        assert_ne!(first, queue_group_id(&hash, "lanectl ping"));
        assert!(first.starts_with(&format!("connector:{hash}:")));
        assert_eq!(first.len(), "connector:".len() + 64 + 1 + ACTION_DIGEST_HEX);
    }

    #[test]
    fn only_the_generic_review_is_non_recognition() {
        assert!(is_non_recognition(Some("native_command_review_required")));
        for code in [
            "native_network_review",
            "native_package_review",
            "native_sensitive_access_review",
            "",
        ] {
            assert!(!is_non_recognition(Some(code)), "{code}");
        }
        assert!(!is_non_recognition(None));
    }

    #[test]
    fn only_a_bare_lowercase_marker_is_completed_per_action() {
        let marker = format!("connector:{}", "a".repeat(64));
        assert!(is_connector_marker(&marker));
        for rejected in [
            format!("connector:{}", "A".repeat(64)),
            format!("connector:{}", "a".repeat(63)),
            format!("{marker}:0123456789abcdef"),
            "approval-group:v1:abc".to_owned(),
        ] {
            assert!(!is_connector_marker(&rejected), "{rejected}");
        }
        let first = action_group_id(&marker, "approval-group:v1:one");
        assert_eq!(first, action_group_id(&marker, "approval-group:v1:one"));
        assert_ne!(first, action_group_id(&marker, "approval-group:v1:two"));
        assert_eq!(first.len(), marker.len() + 1 + ACTION_DIGEST_HEX);
    }

    #[test]
    fn package_scripts_keep_their_surface() {
        let value = payload("local-cli.x", "b", "build", "script", "npm run build");
        assert_eq!(value["surface"], "package-scripts");
        assert_eq!(
            payload("local-cli.y", "c", "lanectl", "binary", "lanectl")["surface"],
            "cli"
        );
    }
}
