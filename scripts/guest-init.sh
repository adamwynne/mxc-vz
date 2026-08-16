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

case "$listen" in
    tcp:*)
        # QEMU test mode: bring up eth0 via DHCP (QEMU user networking).
        /bin/busybox ip link set lo up 2>/dev/null
        /bin/busybox ip link set eth0 up 2>/dev/null
        /bin/busybox udhcpc -i eth0 -n -q -t 10 2>/dev/null
        ;;
esac

echo "mxc-vz guest: starting agent on $listen"
exec /sbin/vz_guest_agent "$listen"
