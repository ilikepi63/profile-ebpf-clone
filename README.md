# Profile EBPF Rust Clone

## Introduction

This is a clone based on [this tutorial](https://eunomia.dev/en/tutorials/12-profile/) to learn some of the constructs surrounding EBPF. This program uses the EBPF perf event in order to sample user space and kernel space stack frames. Blazesym is then used to infer more information from the underlying stack data. 

## Aya

This program uses the Aya EBPF framework in Rust and is structured as per the aya-template. 

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package profile-ebpf-clone --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/profile-ebpf-clone` can be
copied to a Linux server or VM and run there.
err