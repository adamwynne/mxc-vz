#!/bin/busybox sh
# PID 1 of the vz guest (installed as /init by the initramfs overlay,
# overriding Alpine's netboot init). Busybox and its userland come from the
# underlying Alpine initramfs; this script only has to bring up pseudo
# filesystems and hand control to the exec agent.
#
# Kernel cmdline knobs:
#   mxc_agent_listen=<spec>   agent listen spec (default vsock:28024).
#                             tcp:0.0.0.0:7777 is used by the QEMU CI test.
#   mxc_net=static            bring up eth0 with the fixed vz-gate topology
#                             (guest 10.0.2.15/24, gw .2, DNS .3). Set by the
#                             host for FilteredNat (allowedHosts) VMs.

/bin/busybox mkdir -p /proc /sys /dev /tmp
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sysfs /sys 2>/dev/null
/bin/busybox mount -t devtmpfs devtmpfs /dev 2>/dev/null
/bin/busybox mount -t tmpfs tmpfs /tmp 2>/dev/null

# Install busybox applet links so /bin/sh (and friends) exist for the agent's
# /bin/sh -c exec path.
/bin/busybox --install -s /bin 2>/dev/null

listen="vsock:28024"
net=""
for word in $(/bin/busybox cat /proc/cmdline); do
    case "$word" in
        mxc_agent_listen=*) listen="${word#mxc_agent_listen=}" ;;
        mxc_net=*) net="${word#mxc_net=}" ;;
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

# Static network bring-up, shared by QEMU tcp mode (slirp fixes the guest
# at 10.0.2.15) and the vz FilteredNat gate (same topology by design).
# Errors go to the console on purpose: they are the first thing needed
# when debugging a CI boot.
configure_static_net() {
    echo "mxc-vz guest: configuring static network (10.0.2.15/24 via 10.0.2.2)"
    /bin/busybox ip link set lo up || /bin/busybox ifconfig lo up
    /bin/busybox ip link set eth0 up || /bin/busybox ifconfig eth0 up
    /bin/busybox ip addr add 10.0.2.15/24 dev eth0 \
        || /bin/busybox ifconfig eth0 10.0.2.15 netmask 255.255.255.0 \
        || /bin/busybox udhcpc -i eth0 -n -q -t 10
    /bin/busybox ip route add default via 10.0.2.2 dev eth0 2>/dev/null \
        || /bin/busybox route add default gw 10.0.2.2 eth0 2>/dev/null || true
    # The gate's DNS proxy. Convenience only — enforcement is the gate's
    # connect-time IP check, never this file (threat model TM-01).
    echo "nameserver 10.0.2.3" > /etc/resolv.conf 2>/dev/null || true
    /bin/busybox ip addr show eth0 2>/dev/null || /bin/busybox ifconfig eth0
}

case "$listen" in
    tcp:*) configure_static_net ;;
esac
case "$net" in
    static) configure_static_net ;;
esac

echo "mxc-vz guest: starting agent on $listen"
exec /sbin/vz_guest_agent "$listen"
