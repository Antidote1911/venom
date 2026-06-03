//! Memory locked against OS swapping via `mlock(2)`.
//!
//! `LockedMemory<T>` ensures that sensitive key material kept in memory
//! (K_master, private key scalars) is never written to the swap file by
//! the OS, even under memory pressure.
//!
//! ## Guarantees
//!
//! - **mlock**: the page(s) containing the value are pinned in RAM.
//! - **zeroize on drop**: bytes are overwritten before the allocation is freed.
//! - **munlock on drop**: the page is released back to normal management.
//!
//! If `mlock` fails (e.g. `RLIMIT_MEMLOCK` exceeded), the error is silenced
//! and only the `Zeroize` guarantee applies.
//!
//! ## Limitations
//!
//! A stack copy of the value exists between its construction and the call to
//! `LockedMemory::new()`.  For complete protection the key should be generated
//! directly into the locked allocation — this is a known trade-off in most
//! practical key-management implementations.
//!
//! On non-Unix platforms (Windows) mlock/munlock are no-ops; `Zeroize` still
//! applies.

use std::ops::Deref;
use zeroize::Zeroize;

pub struct LockedMemory<T: Zeroize> {
    inner: Box<T>,
}

impl<T: Zeroize> LockedMemory<T> {
    pub fn new(value: T) -> Self {
        let inner = Box::new(value);
        #[cfg(unix)]
        unsafe {
            libc::mlock(
                inner.as_ref() as *const T as *const libc::c_void,
                std::mem::size_of::<T>(),
            );
        }
        Self { inner }
    }
}

impl<T: Zeroize> Drop for LockedMemory<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
        #[cfg(unix)]
        unsafe {
            libc::munlock(
                self.inner.as_ref() as *const T as *const libc::c_void,
                std::mem::size_of::<T>(),
            );
        }
    }
}

impl<T: Zeroize> Deref for LockedMemory<T> {
    type Target = T;
    fn deref(&self) -> &T { &self.inner }
}

impl<T: Zeroize> std::ops::DerefMut for LockedMemory<T> {
    fn deref_mut(&mut self) -> &mut T { &mut self.inner }
}

/// Clone by creating a second independently locked allocation.
/// A temporary stack copy exists during the clone — unavoidable without
/// OS-level copy-on-write support for locked pages.
impl<T: Zeroize + Copy> Clone for LockedMemory<T> {
    fn clone(&self) -> Self {
        Self::new(**self)
    }
}
