//! Library for Profile related tools.

#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(missing_docs)]

use std::ffi::CStr;
use std::num::NonZero;

use blazesym::symbolize::{Input, Source, Symbolizer};
use log::info;
use profile_ebpf_clone_common::StackTraceEvent;

/// Function to input a stack trace and display it using blazesym.
fn show_stack_trace(stack: &[u64], pid: i32) -> anyhow::Result<()> {
    let src = Source::Process(blazesym::symbolize::Process::new(blazesym::Pid::Pid(
        unsafe { NonZero::new_unchecked(pid.try_into()?) },
    )));
    let symbolizer = Symbolizer::new();
    let syms = symbolizer.symbolize(&src, Input::AbsAddr(stack))?;

    for symbolized in syms {
        match symbolized {
            blazesym::symbolize::Symbolized::Sym(sym) => {
                dbg!(sym);
            }
            blazesym::symbolize::Symbolized::Unknown(_) => {}
        }
    }

    Ok(())
}

/// Function to handle the StackTraceEvent, displaying it to stdout.
pub fn event_handler(event: &StackTraceEvent) -> anyhow::Result<()> {
    if event.kstack_sz <= 0 && event.ustack_sz <= 0 {
        // Early return as both stack sizes are 0.
        return Ok(());
    }

    let comm = unsafe { CStr::from_ptr(event.comm.as_ptr()).to_string_lossy() };
    info!("COMM: {} (pid={}) @ CPU {}", comm, event.pid, event.cpu_id);

    if event.kstack_sz > 0 {
        info!("Kernel:");
        show_stack_trace(&event.kstack, 0)?;
    } else {
        info!("No Kernel Stack");
    }

    if event.ustack_sz > 0 {
        info!("Userspace:");
        show_stack_trace(&event.ustack, event.pid.try_into()?)?;
    } else {
        info!("No Userspace Stack");
    }

    Ok(())
}
