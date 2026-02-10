use crate::constants::{
    FALLBACK_NAME_ATTEMPTS, FALLBACK_NAME_DEFAULT, FALLBACK_NAME_SUFFIX_OFFSET,
    FALLBACK_NAME_SUFFIX_START, PSEUDO_RANDOM_MIX_A, PSEUDO_RANDOM_MIX_B,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const ADJECTIVES: &[&str] = &[
    "pink", "brisk", "crisp", "lucky", "quiet", "rapid", "sunny", "tidy", "witty", "bold", "swift",
    "fuzzy",
];
const NOUNS: &[&str] = &[
    "elephant", "otter", "falcon", "harbor", "forest", "rocket", "lantern", "meadow", "beacon",
    "comet", "panther", "sailor",
];

pub(crate) fn fallback_workspace_name(worktrees_dir: &Path) -> String {
    for attempt in 0..FALLBACK_NAME_ATTEMPTS {
        let adjective = ADJECTIVES[pseudo_random_index(ADJECTIVES.len(), attempt)];
        let noun = NOUNS[pseudo_random_index(NOUNS.len(), attempt + FALLBACK_NAME_SUFFIX_OFFSET)];
        let base = format!("{adjective} {noun}");
        if !worktrees_dir.join(&base).exists() {
            return base;
        }
        let with_suffix = format!("{base} {}", attempt + FALLBACK_NAME_SUFFIX_START);
        if !worktrees_dir.join(&with_suffix).exists() {
            return with_suffix;
        }
    }

    FALLBACK_NAME_DEFAULT.to_string()
}

fn pseudo_random_index(len: usize, salt: u64) -> usize {
    if len == 0 {
        return 0;
    }

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let mut value = nanos ^ pid.rotate_left(17) ^ salt.wrapping_mul(PSEUDO_RANDOM_MIX_A);
    value ^= value >> 33;
    value = value.wrapping_mul(PSEUDO_RANDOM_MIX_B);
    value ^= value >> 33;
    (value as usize) % len
}
