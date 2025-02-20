//! Shared logic related to both user space and kernel space programs.
#![no_std]

#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(missing_docs)]

// REFERENCE: https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/profile.h

use core::ffi::c_long;

/// Task Comm Length in Bytes.
pub const TASK_COMM_LEN: usize = 16;

/// Max Stack depth - used to sample the amount of pointers pulled from the stack.
pub const MAX_STACK_DEPTH: usize = 128;

/// The slice used in extracting stack function pointers. 
pub type StackTrace = [u64; MAX_STACK_DEPTH];


/// A generic stack trace event. This data structure is used to communicate this data 
/// between user space and kernel space.
#[derive(Debug)]
pub struct StackTraceEvent {
    /// Process ID for the sample.
    pub pid: u32,
    /// CPU ID for the sample.
    pub cpu_id: u32,
    /// The comm of the current sample.
    pub comm: [i8; TASK_COMM_LEN],
    /// Size of the kernel space stack. 
    pub kstack_sz: c_long,
    /// Size of the user space stack.
    pub ustack_sz: c_long,
    /// The actual kernel stack.
    pub kstack: StackTrace,
    /// The user space stack.
    pub ustack: StackTrace,
}

impl StackTraceEvent {

    /// Helper method to get kernel space stack size.
    #[inline(always)]
    pub fn kstack_size() -> Result<u32, u32> {
        core::mem::size_of::<StackTrace>().try_into().map_err(|_| 1)
    }

    /// Helper method to get user space stack size.
    #[inline(always)]
    pub fn ustack_size() -> Result<u32, u32> {
        core::mem::size_of::<StackTrace>().try_into().map_err(|_| 1)
    }
}
