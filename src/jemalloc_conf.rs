//! Compile-time jemalloc configuration override.
//!
//! jemalloc reads its `malloc_conf` string (and, through it, all `opt.*`
//! options) **once**, during the first allocation — before `main()` runs.
//! Options like `dirty_decay_ms` / `muzzy_decay_ms` / `background_thread`
//! are `opt.*` mallctls and therefore cannot be changed at runtime.
//!
//! jemalloc exports the hook `malloc_conf` (here `_rjem_malloc_conf`, the
//! prefixed symbol) as a *weak* global.  Defining a strong symbol with the
//! same name in this crate overrides it, exactly as jemalloc's own
//! `malloc_conf_set` test does.  The linker resolves the strong definition
//! and jemalloc initializes with these options.
//!
//! Only compiled under the `jemalloc` feature, and only on targets where
//! tikv-jemalloc-sys uses the `_rjem_` prefix (GNU/ELF; Apple targets keep
//! the unprefixed `malloc_conf`).  See `tikv-jemalloc-sys` build.rs.
//!
//! `background_thread:true` requires the `background_threads` cargo feature
//! of `tikv-jemalloc-sys` (enabled in Cargo.toml), otherwise jemalloc is
//! built without runtime background-thread support and rejects the option.

#![cfg(feature = "jemalloc")]

use std::ffi::c_char;

/// Strong definition overriding jemalloc's weak `_rjem_malloc_conf`.
///
/// Options:
/// - `background_thread:true` — jemalloc spawns a background thread that
///   performs decay/purge, so freed pages are returned to the OS without
///   blocking query threads.
/// - `dirty_decay_ms:1000` / `muzzy_decay_ms:1000` — return dirty/muzzy
///   pages to the OS ~1s after they are freed instead of the default 10s,
///   so reload-related memory (e.g. old group/hosts tries) drops promptly.
///
/// Keep it a single static; the C string must be NUL-terminated and live
/// for the whole process.
#[cfg(all(
    feature = "jemalloc",
    any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")
))]
#[no_mangle]
pub static _rjem_malloc_conf: Option<&'static c_char> = Some(unsafe {
    // SAFETY: `c"..."` yields a static, NUL-terminated C string that lives
    // for the whole process; `c_char` is plain `i8` on the supported targets
    // and the reference points at the first character.
    &*c"background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:1000".as_ptr()
});

#[cfg(test)]
mod tests {
    #[test]
    fn test_conf_override_is_set() {
        // 与 tikv-jemalloc-sys::malloc_conf 对比：必须是 Some 且包含我们的配置。
        // SAFETY: reading the extern static pointer; jemalloc initialized it
        // before main, and it points to a valid NUL-terminated C string.
        let sys = unsafe { tikv_jemalloc_sys::malloc_conf };
        assert!(sys.is_some(), "jemalloc malloc_conf should be overridden; got None");
        let s = unsafe { std::ffi::CStr::from_ptr(sys.unwrap()) }
            .to_string_lossy()
            .into_owned();
        assert!(s.contains("background_thread:true"), "got: {s}");
        assert!(s.contains("dirty_decay_ms:1000"), "got: {s}");
        assert!(s.contains("muzzy_decay_ms:1000"), "got: {s}");
    }
}
