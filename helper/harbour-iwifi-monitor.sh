#!/bin/sh
# harbour-iwifi Tier-3 monitor helper (runs as root, started by udev/systemd when
# the Alfa RTL8812AU is plugged in). Loads the driver, puts the adapter into
# monitor mode and execs the 802.11 sniffer.
modprobe 8812au 2>/dev/null

# find the RTL8812AU's interface (usually wlan1); fall back to wlan1
IF=""
for n in /sys/class/net/*; do
    dev="$n/device"
    if [ -e "$dev/idVendor" ] && [ "$(cat "$dev/idVendor" 2>/dev/null)" = "0bda" ] \
       && [ "$(cat "$dev/idProduct" 2>/dev/null)" = "8812" ]; then
        IF="$(basename "$n")"; break
    fi
done
[ -n "$IF" ] || IF=wlan1

# wait for the interface to exist
i=0
while [ ! -e "/sys/class/net/$IF" ] && [ "$i" -lt 20 ]; do sleep 0.3; i=$((i+1)); done
[ -e "/sys/class/net/$IF" ] || exit 0

ip link set "$IF" down 2>/dev/null
iw dev "$IF" set type monitor 2>/dev/null
ip link set "$IF" up 2>/dev/null

exec /usr/bin/harbour-iwifi-sniff "$IF" /tmp/iwifi-sniff.json
