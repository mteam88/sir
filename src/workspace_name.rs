use crate::constants::{
    FALLBACK_NAME_SUFFIX_OFFSET, FALLBACK_NAME_SUFFIX_START, PSEUDO_RANDOM_MIX_A,
    PSEUDO_RANDOM_MIX_B,
};
use std::time::{SystemTime, UNIX_EPOCH};

const ADJECTIVES: &[&str] = &[
    "pink", "brisk", "crisp", "lucky", "quiet", "rapid", "sunny", "tidy", "witty", "bold", "swift",
    "fuzzy",
];
const NOUNS: &[&str] = &[
    "elephant", "otter", "falcon", "harbor", "forest", "rocket", "lantern", "meadow", "beacon",
    "comet", "panther", "sailor",
];

pub(crate) fn fallback_workspace_name_candidate(attempt: u64) -> String {
    let adjective = ADJECTIVES[pseudo_random_index(ADJECTIVES.len(), attempt)];
    let noun = NOUNS[pseudo_random_index(NOUNS.len(), attempt + FALLBACK_NAME_SUFFIX_OFFSET)];
    let base = format!("{adjective} {noun}");
    if attempt == 0 {
        return base;
    }
    format!("{base} {}", attempt + FALLBACK_NAME_SUFFIX_START)
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
