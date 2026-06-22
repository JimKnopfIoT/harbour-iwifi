#!/bin/sh
# harbour-iwifi — bring the external RTL8812AU adapter up in monitor mode.
# Run as ExecStartPre of harbour-iwifi-monitor.service (root). Idempotent.
set -e

# Load the out-of-tree driver if the adapter is plugged in (udev usually does
# this already on hotplug; harmless if it's a no-op or already loaded).
modprobe 8812au 2>/dev/null || true

# Wait for wlan1 to appear (driver bind can lag a moment after modprobe).
i=0
while [ $i -lt 10 ]; do
    if ip link show wlan1 >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 0.5
done

# No adapter → fail so the service doesn't pretend to be capturing.
ip link show wlan1 >/dev/null 2>&1 || {
    echo "harbour-iwifi: wlan1 not present (no external adapter?)" >&2
    exit 1
}

# Put it into monitor mode (the sniffer hops channels itself).
ip link set wlan1 down
iw dev wlan1 set type monitor
ip link set wlan1 up
exit 0
