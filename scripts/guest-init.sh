#!/bin/busybox sh
# PID 1 of the vz guest (installed as /init by the initramfs overlay,
# overriding Alpine's netboot init). Busybox and its userland come from the
# underlying Alpine initramfs; this script only has to bring up pseudo
# filesystems and hand control to the exec agent.
#
# Kernel cmdline knobs:
#   mxc_agent_listen=<spec>   agent listen spec (default vsock:28024).
#                             tcp:0.0.0.0:7777 is used by the QEMU CI test.

/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sysfs /sys 2>/dev/null
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null
/bin/busybox mount -t tmpfs tmpfs /tmp 2>/dev/null

# Install busybox applet links so /bin/sh (and friends) exist for the agent's
# /bin/sh -c exec path.
/bin/busybox --install -s /bin 2>/dev/null

listen="vsock:28024"
for word in $(/bin/busybox cat /proc/cmdline); do
    case "$word" in
        mxc_agent_listen=*) listen="${word#mxc_agent_listen=}" ;;
    esac
done

# The Alpine netboot kernel ships virtio drivers as modules carried in the
# initramfs (its own init modprobes them; ours must too). The plan's final
# monolithic kernel removes this step. Best-effort: names differ across
# kernel versions, and some may be built in.
echo "mxc-vz guest: loading virtio modules"
for module in virtio_pci virtio_mmio virtio_net virtio_vsock vmw_vsock_virtio_transport; do
    /bin/busybox modprobe "$module" 2>/dev/null || true
done

case "$listen" in
    tcp:*)
        # QEMU test mode (user networking / slirp). The guest address is
        # fixed at 10.0.2.15/24 — configure it statically so we do not
        # depend on a udhcpc applet being present; try udhcpc as backup.
        # Errors go to the console on purpose: they are the first thing
        # needed when debugging a CI boot.
        echo "mxc-vz guest: configuring network for tcp mode"
        /bin/busybox ip link set lo up || /bin/busybox ifconfig lo up
        /bin/busybox ip link set eth0 up || /bin/busybox ifconfig eth0 up
        /bin/busybox ip addr add 10.0.2.15/24 dev eth0 \
            || /bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 \
            || /bin/busybox udhcpc -i eth0 -n -q -t 10
        /bin/busybox ip addr show eth0 2>/dev/null || /bin/busybox ifconfig eth0
        ;;
esac

echo "mxc-vz guest: starting agent on $listen"
exec /sbin/vz_guest_agent "$listen"
