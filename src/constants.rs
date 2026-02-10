pub(crate) const DEFAULT_SHELL: &str = "sh";
pub(crate) const DEFAULT_WORKSPACE_REVISION: &str = "HEAD";

pub(crate) const FALLBACK_NAME_ATTEMPTS: u64 = 100;
pub(crate) const FALLBACK_NAME_SUFFIX_OFFSET: u64 = 97;
pub(crate) const FALLBACK_NAME_SUFFIX_START: u64 = 2;
pub(crate) const FALLBACK_NAME_DEFAULT: &str = "pink elephant";

pub(crate) const PSEUDO_RANDOM_MIX_A: u64 = 0x9E37_79B9_7F4A_7C15;
pub(crate) const PSEUDO_RANDOM_MIX_B: u64 = 0xFF51_AFD7_ED55_8CCD;

pub(crate) const RESERVED_WORKTREE_LOGS: &str = "_logs";
pub(crate) const RESERVED_WORKTREE_TMP: &str = "_tmp";

pub(crate) const STATUS_SUMMARY_MAX_LINES: usize = 3;
pub(crate) const STATUS_TRUNCATE_MAX_CHARS: usize = 100;
pub(crate) const TRUNCATE_ELLIPSIS_CHARS: usize = 3;
pub(crate) const PORCELAIN_STATUS_MIN_BYTES: usize = 2;
