//! The Userspace program related to this EBPF program.
#![deny(clippy::print_stderr)]
#![deny(clippy::print_stdout)]
#![deny(missing_docs)]

use aya::{
    maps::AsyncPerfEventArray,
    programs::{perf_event, PerfEvent},
    util::online_cpus,
};
use bytes::BytesMut;

use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use profile_ebpf_clone::event_handler;
use profile_ebpf_clone_common::StackTraceEvent;
use tokio::signal;
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/profile-ebpf-clone"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // List Online CPUs
    let cpus = online_cpus().map_err(|(_, error)| error)?;
    let num_cpus = cpus.len();

    // Load and attach programs.
    let program: &mut PerfEvent = ebpf.program_mut("ebpf_example").unwrap().try_into()?;
    program.load()?;

    for cpu in cpus.clone() {
        program.attach(
            perf_event::PerfTypeId::Software,
            perf_event::perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
            perf_event::PerfEventScope::AllProcessesOneCpu { cpu },
            perf_event::SamplePolicy::Frequency(1),
            true,
        )?;
    }

    // Extract the events map.
    let mut events: AsyncPerfEventArray<aya::maps::MapData> =
        AsyncPerfEventArray::try_from(ebpf.take_map("EVENTS").unwrap())?;

    // iterate through the cpus, handling events from each,#![deny(clippy::print_stderr)]
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const StackTraceEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    let _ = event_handler(&data);
                }
            }
        });
    }

    // let mut events = AsyncPerfEventArray::try_from(ebpf.map_mut("EVENTS").unwrap())?;

    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    Ok(())
}
