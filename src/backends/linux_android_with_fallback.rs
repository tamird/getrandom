//! Implementation for Linux / Android with `/dev/urandom` fallback
use super::use_file;
use crate::Error;
use core::{
    ffi::c_void,
    mem::{MaybeUninit, transmute},
    ptr,
};
use use_file::utils;

pub use crate::util::{inner_u32, inner_u64};

#[path = "../lazy.rs"]
mod lazy;

type GetRandomFn = unsafe extern "C" fn(*mut c_void, libc::size_t, libc::c_uint) -> libc::ssize_t;

#[cold]
#[inline(never)]
fn is_getrandom_good(getrandom_fn: GetRandomFn) -> bool {
    if cfg!(getrandom_test_linux_fallback) {
        false
    } else {
        // Check that `getrandom` syscall is supported by kernel.
        let res = unsafe { getrandom_fn(ptr::dangling_mut(), 0, 0) };
        if !res.is_negative() {
            true
        } else {
            match utils::get_errno() {
                libc::ENOSYS => false, // No kernel support.
                // The fallback on EPERM is intentionally not done on Android since this workaround
                // seems to be needed only for specific Linux-based products that aren't based
                // on Android. See https://github.com/rust-random/getrandom/issues/229.
                libc::EPERM if cfg!(target_os = "linux") => false, // Blocked by seccomp.
                _ => true,
            }
        }
    }
}

fn to_getrandom_fn(getrandom_fn: usize) -> GetRandomFn {
    unsafe { transmute::<usize, GetRandomFn>(getrandom_fn) }
}

#[cold]
#[inline(never)]
fn init() -> Option<usize> {
    ptr::NonNull::new(unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"getrandom".as_ptr()) }).and_then(
        |getrandom_fn| {
            let getrandom_fn = to_getrandom_fn(getrandom_fn.as_ptr() as usize);
            is_getrandom_good(getrandom_fn).then_some(getrandom_fn as usize)
        },
    )
}

// Prevent inlining of the fallback implementation.
#[inline(never)]
fn use_file_fallback(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    use_file::fill_inner(dest)
}

#[inline]
pub fn fill_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    if cfg!(not(target_feature = "crt-static")) {
        static GETRANDOM_FN: lazy::LazyUsize = lazy::LazyUsize::new();

        const NOT_AVAILABLE: usize = usize::MAX;

        match GETRANDOM_FN.unsync_init(|| init().unwrap_or(NOT_AVAILABLE)) {
            NOT_AVAILABLE => {
                if cfg!(getrandom_test_linux_without_fallback) {
                    panic!("fallback is triggered with `getrandom_test_linux_without_fallback`");
                }
                use_file_fallback(dest)
            }
            getrandom_fn => {
                let getrandom_fn = to_getrandom_fn(getrandom_fn);
                utils::sys_fill_exact(dest, |buf| unsafe {
                    getrandom_fn(buf.as_mut_ptr().cast(), buf.len(), 0)
                })
            }
        }
    } else if cfg!(has_libc_getrandom) {
        use_file::fill_inner(dest)
    } else {
        static GETRANDOM_GOOD: lazy::LazyBool = lazy::LazyBool::new();

        if GETRANDOM_GOOD.unsync_init(|| is_getrandom_good(libc::getrandom)) {
            utils::sys_fill_exact(dest, |buf| unsafe {
                libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0)
            })
        } else {
            use_file_fallback(dest)
        }
    }
}
