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
    for attempt in 0..100u64 {
        let adjective = ADJECTIVES[pseudo_random_index(ADJECTIVES.len(), attempt)];
        let noun = NOUNS[pseudo_random_index(NOUNS.len(), attempt + 97)];
        let base = format!("{adjective} {noun}");
        if !worktrees_dir.join(&base).exists() {
            return base;
        }
        let with_suffix = format!("{base} {}", attempt + 2);
        if !worktrees_dir.join(&with_suffix).exists() {
            return with_suffix;
        }
    }

    "pink elephant".to_string()
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
    let mut value = nanos ^ pid.rotate_left(17) ^ salt.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    value ^= value >> 33;
    value = value.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    value ^= value >> 33;
    (value as usize) % len
}
