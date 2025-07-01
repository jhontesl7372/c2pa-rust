//! Unsafe proof-of-concept tests verifying UB in internal JUMBF code.
//!
//! These are **crate-local** tests so they can access `crate::jumbf` internals
//! that aren’t re-exported publicly.  Run under Miri:
//!
//! ```bash
//! cargo +nightly miri test -p c2pa --lib unsafe_poc
//! ```

#[cfg(test)]
mod tests {
    use crate::jumbf::boxes::JUMBFDescriptionBox;

    /// Triggers UB by passing a label containing an interior NUL to
    /// `JUMBFDescriptionBox::from`, which internally performs
    /// `CString::from_vec_unchecked` without validating the bytes.
    #[test]
    fn jumbf_desc_box_interior_nul() {
        // 16-byte dummy UUID
        let uuid = [0u8; 16];
        // label with interior NUL ⇒ violates CString invariant
        let label = b"bad\0label".to_vec();
        // UB should be detected by Miri
        let _ = JUMBFDescriptionBox::from(&uuid, 0, label, None, None, None);
    }
}
