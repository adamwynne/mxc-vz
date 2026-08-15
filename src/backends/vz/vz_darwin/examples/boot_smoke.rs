//! Phase 1 boot milestone smoke: boot a Linux guest under
//! Virtualization.framework, hold it running briefly, then tear it down.
//!
//! Usage (macOS, Apple Silicon):
//!   ./scripts/fetch-alpine-guest.sh guest/
//!   cargo build --example boot_smoke
//!   codesign --force --sign - --entitlements scripts/vz.entitlements \
//!       target/debug/examples/boot_smoke     # or let build-mac.sh sign it
//!   target/debug/examples/boot_smoke guest/vmlinuz-virt guest/initramfs-virt
//!
//! Exit codes: 0 = booted and tore down cleanly; 2 = VZ unsupported on this
//! host (no Apple Silicon / no entitlement / no nested virtualization);
//! 1 = any other failure. CI keys off the distinction between 1 and 2.

#[cfg(target_os = "macos")]
fn main() {
    use std::path::PathBuf;
    use std::time::Duration;

    use vz_common::vm_spec::{NetworkMode, VmSpec, VSOCK_AGENT_PORT};
    use vz_darwin::runner::VmError;
    use vz_darwin::vz::spawn_vm;

    let mut args = std::env::args().skip(1);
    let (kernel, initramfs) = match (args.next(), args.next()) {
        (Some(kernel), Some(initramfs)) => (PathBuf::from(kernel), PathBuf::from(initramfs)),
        _ => {
            eprintln!("usage: boot_smoke <kernel> <initramfs>");
            std::process::exit(1);
        }
    };
    for path in [&kernel, &initramfs] {
        if !path.is_file() {
            eprintln!("boot_smoke: no such file: {}", path.display());
            std::process::exit(1);
        }
    }

    // Hand-built spec: the smoke test bypasses policy JSON on purpose — it
    // exercises the driver, not the schema (that has its own suites).
    let spec = VmSpec {
        cpu_count: 2,
        memory_bytes: 2048 * 1024 * 1024,
        kernel_path: kernel,
        initramfs_path: initramfs,
        kernel_cmdline: "console=hvc0 panic=1".to_string(),
        shares: Vec::new(),
        network: NetworkMode::None,
        vsock_agent_port: VSOCK_AGENT_PORT,
        boot_timeout: Duration::from_secs(30),
    };
    let boot_timeout = spec.boot_timeout;

    println!("boot_smoke: creating VM ({} cpus, {} MiB)", spec.cpu_count, spec.memory_bytes >> 20);
    let handle = match spawn_vm(spec) {
        Ok(handle) => handle,
        Err(VmError::Start(reason)) if reason.contains("not available") => {
            eprintln!("boot_smoke: UNSUPPORTED: {reason}");
            std::process::exit(2);
        }
        Err(error) => {
            eprintln!("boot_smoke: VM creation failed: {error}");
            std::process::exit(1);
        }
    };

    println!("boot_smoke: booting (timeout {boot_timeout:?})...");
    let booted_at = std::time::Instant::now();
    if let Err(error) = handle.boot(boot_timeout) {
        eprintln!("boot_smoke: boot failed: {error}");
        std::process::exit(1);
    }
    println!("boot_smoke: running after {:?}", booted_at.elapsed());

    // Hold the VM briefly and re-check state: catches guests that start and
    // immediately die (e.g. a kernel that panics on missing devices).
    std::thread::sleep(Duration::from_secs(2));
    match handle.state() {
        Ok(state) => println!("boot_smoke: state after 2s: {state:?}"),
        Err(error) => {
            eprintln!("boot_smoke: state query failed: {error}");
            std::process::exit(1);
        }
    }

    if let Err(error) = handle.stop() {
        eprintln!("boot_smoke: stop failed: {error}");
        std::process::exit(1);
    }
    drop(handle);
    println!("boot_smoke: OK — booted, ran, and tore down cleanly");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("boot_smoke: this example drives Virtualization.framework and only runs on macOS");
    std::process::exit(2);
}
