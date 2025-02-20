//! The Kernel space part of this EBPF program.
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::BPF_F_USER_STACK,
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_smp_processor_id,
        gen::bpf_get_stack,
    },
    macros::{map, perf_event},
    maps::{PerCpuArray, PerfEventArray},
    programs::PerfEventContext,
    EbpfContext,
};
use profile_ebpf_clone_common::StackTraceEvent;

#[map]
static mut EVENTS: PerfEventArray<StackTraceEvent> = PerfEventArray::new(0);

#[map]
static mut SCRATCH: PerCpuArray<StackTraceEvent> = PerCpuArray::with_max_entries(1, 0);

#[perf_event]
pub fn ebpf_example(ctx: PerfEventContext) -> u32 {
    match try_ebpf_example(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_ebpf_example(ctx: PerfEventContext) -> Result<u32, u32> {
    // References to this static are allowed.
    #[allow(static_mut_refs)]
    if let Some(event_ptr) = unsafe { SCRATCH.get_ptr_mut(0) } {
        let event: &mut StackTraceEvent = unsafe { &mut *event_ptr };

        let pid = bpf_get_current_pid_tgid() as u32;
        (*event).pid = pid;

        let cpu_id = unsafe { bpf_get_smp_processor_id() };

        (*event).cpu_id = cpu_id;

        let comm = bpf_get_current_comm().map_err(|_| 1_u32)?;
        unsafe { (*event).comm = core::mem::transmute(comm) };

        let kstack_ptr = (*event).kstack.as_mut_ptr() as *mut c_void;
        let ustack_ptr = (*event).ustack.as_mut_ptr() as *mut c_void;

        let kstack_sz =
            unsafe { bpf_get_stack(ctx.as_ptr(), kstack_ptr, StackTraceEvent::kstack_size()?, 0) };

        let ustack_sz = unsafe {
            bpf_get_stack(
                ctx.as_ptr(),
                ustack_ptr,
                StackTraceEvent::ustack_size()?,
                BPF_F_USER_STACK.into(),
            )
        };

        (*event).kstack_sz = kstack_sz;
        (*event).ustack_sz = ustack_sz;

        unsafe { EVENTS.output(&ctx, event, 0) };
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
