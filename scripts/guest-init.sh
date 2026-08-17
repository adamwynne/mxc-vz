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
#   mxc_probe_egress=<allowed_url>,<denied_url>,<refused_url>
#                             CI-only: probe the egress gate with wget and
#                             print MXC_EGRESS_* sentinels on the console,
#                             then power off (no agent starts). The first
#                             URL must fetch; the other two must fail
#                             (RST-denied IP / DNS-refused name).

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
probe_egress=""
for word in $(/bin/busybox cat /proc/cmdline); do
    case "$word" in
        mxc_agent_listen=*) listen="${word#mxc_agent_listen=}" ;;
        mxc_net=*) net="${word#mxc_net=}" ;;
        mxc_probe_egress=*) probe_egress="${word#mxc_probe_egress=}" ;;
    esac
done

# The Alpine netboot kernel ships virtio drivers as modules carried in the
# initramfs (its own init modprobes them; ours must too). The plan's final
# monolithic kernel removes this step. Best-effort: names differ across
# kernel versions, and some may be built in.
echo "mxc-vz guest: loading virtio modules"
for module in virtio_pci virtio_mmio virtio_net fuse virtiofs; do
    /bin/busybox modprobe "$module" 2>/dev/null || true
done

# AF_VSOCK is the host<->guest control channel. Alpine's -virt initramfs ships
# no virtio-vsock module, so the guest build stages the version-matched .ko
# under /mxc-modules (scripts/build-vz-guest.sh via extract-modloop-
# modules.py). A top-level dir on purpose: overlaying /lib would shadow the
# base initramfs's /lib (musl loader) and brick busybox. insmod in dependency
# order: core -> common -> transport.
echo "mxc-vz guest: loading vsock modules"
for ko in vsock vmw_vsock_virtio_transport_common vmw_vsock_virtio_transport; do
    f="/mxc-modules/$ko.ko"
    if [ ! -f "$f" ]; then
        echo "  $ko.ko: MISSING from image"
    elif /bin/busybox insmod "$f" 2>/tmp/insmod.err; then
        echo "  $ko.ko: loaded"
    else
        echo "  $ko.ko: insmod FAILED: $(/bin/busybox cat /tmp/insmod.err 2>/dev/null)"
    fi
done
echo "mxc-vz guest: AF_VSOCK present: $([ -d /sys/module/vsock ] && echo yes || echo no)"

# Mount virtio-fs shares the host declared on the cmdline as
# `mxc_share=<tag>:<ro|rw>:<path>` tokens (vz_common::vm_spec). The host owns
# read-only enforcement (VZSharedDirectory.readOnly) — mounting a ro share
# `-o ro` here is only defence in depth; a guest remount,rw still cannot write
# because the host backend rejects it (threat model TM-03). Paths never carry
# whitespace (validation rejects that), so cmdline word-splitting is safe.
for word in $(/bin/busybox cat /proc/cmdline); do
    case "$word" in
        mxc_share=*)
            spec="${word#mxc_share=}"
            tag="${spec%%:*}"
            rest="${spec#*:}"
            mode="${rest%%:*}"
            path="${rest#*:}"
            [ -n "$tag" ] && [ -n "$path" ] || continue
            /bin/busybox mkdir -p "$path"
            if [ "$mode" = "ro" ]; then
                /bin/busybox mount -t virtiofs -o ro "$tag" "$path" \
                    && echo "mxc-vz guest: mounted ro share $tag at $path" \
                    || echo "mxc-vz guest: FAILED to mount ro share $tag at $path"
            else
                /bin/busybox mount -t virtiofs "$tag" "$path" \
                    && echo "mxc-vz guest: mounted rw share $tag at $path" \
                    || echo "mxc-vz guest: FAILED to mount rw share $tag at $path"
            fi
            ;;
    esac
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
    # IPv6 mirror of the same topology (ULA fd00:6d78:63::/64); best-effort
    # so a v4-only kernel still boots.
    /bin/busybox ip -6 addr add fd00:6d78:63::15/64 dev eth0 2>/dev/null || true
    /bin/busybox ip -6 route add default via fd00:6d78:63::2 dev eth0 2>/dev/null || true
    # The gate's DNS proxy. Convenience only — enforcement is the gate's
    # connect-time IP check, never this file (threat model TM-01).
    {
        echo "nameserver 10.0.2.3"
        echo "nameserver fd00:6d78:63::3"
    } > /etc/resolv.conf 2>/dev/null || true
    /bin/busybox ip addr show eth0 2>/dev/null || /bin/busybox ifconfig eth0
}

case "$listen" in
    tcp:*) configure_static_net ;;
esac
case "$net" in
    static) configure_static_net ;;
esac

# Egress gate probe (CI): three wgets against the gate, sentinels to the
# console, then power off. Runs INSTEAD of the agent.
if [ -n "$probe_egress" ]; then
    allowed_url="${probe_egress%%,*}"
    rest="${probe_egress#*,}"
    denied_url="${rest%%,*}"
    refused_url="${rest#*,}"

    echo "mxc-vz guest: egress probe starting"
    if /bin/busybox wget -q -T 20 -O /tmp/egress-allowed "$allowed_url"; then
        echo "MXC_EGRESS_ALLOWED_OK"
    else
        echo "MXC_EGRESS_ALLOWED_FAIL"
    fi
    if /bin/busybox wget -q -T 8 -O /dev/null "$denied_url" 2>/dev/null; then
        echo "MXC_EGRESS_DENIED_FAIL"
    else
        echo "MXC_EGRESS_DENIED_OK"
    fi
    if /bin/busybox wget -q -T 8 -O /dev/null "$refused_url" 2>/dev/null; then
        echo "MXC_EGRESS_REFUSED_FAIL"
    else
        echo "MXC_EGRESS_REFUSED_OK"
    fi
    echo "MXC_EGRESS_PROBE_COMPLETE"
    /bin/busybox poweroff -f
    exit 0
fi

echo "mxc-vz guest: starting agent on $listen"
exec /sbin/vz_guest_agent "$listen"
