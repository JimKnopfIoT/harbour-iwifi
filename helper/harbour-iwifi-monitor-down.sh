#!/bin/sh
# harbour-iwifi — tear the adapter back down when the sniffer stops, to cut the
# power draw (continuous monitor-mode RX is what flattens the battery).
# Run as ExecStopPost of harbour-iwifi-monitor.service (root).
ip link set wlan1 down 2>/dev/null || true
# leave the module loaded; udev autoloads it on hotplug anyway and re-modprobe
# on every foreground would add latency. Down'd interface draws far less.
rm -f /tmp/iwifi-sniff.json 2>/dev/null || true
exit 0
