<p align="center">
  <img src="icons/256x256/harbour-iwifi.png" width="128" alt="iWifi logo">
</p>

<h1 align="center">iWifi — a WLAN security checker for Sailfish OS</h1>

iWifi turns a Sailfish OS phone into a passive Wi‑Fi **security checker**. It goes
beyond plain network analysis: a heading‑up **radar** of the APs around you, a
per‑hotspot **security assessment**, **CVE** lookup for the router model, and an
optional **Tier‑3 monitor mode** (via an external USB adapter) that *defensively*
detects deauthentication attacks and evil‑twin APs and shows how many clients are
connected to a network.

The app is **purely passive** — it never transmits, never injects frames, never
cracks anything, never decrypts traffic. See **Legal & responsible use** below.

Developed and tested on a **Sony Xperia 10 III** (`pdx213`) running Sailfish OS.
That is the only device it has actually been verified on — much of it should work
on other Sailfish devices too, but treat anything else as untested. The Tier‑3
monitor driver below is built specifically against the Xperia 10 III kernel.

---

## Features

- **Radar** (entry screen): heading‑up view of nearby APs; tap a corner chart to
  filter by channel or RSSI; 2.4/5 GHz band filter; pin hotspots. Optional GPS
  fix and an opt‑in OpenStreetMap silhouette background.
- **Network list** → **detail view** per hotspot: vendor (from the BSSID OUI),
  band/channel, signal and a rough distance estimate, security classification
  (open / WEP / WPA2 / WPA3 / WPA3‑transition / Enterprise), cipher, PMF/802.11w,
  advertised client count (BSS load), country, hidden‑SSID and randomized‑MAC
  flags, and WPS device info.
- **CVE lookup** for the router model (NIST NVD) with a CISA "known‑exploited"
  (KEV) flag and an Exploit‑DB link.
- **Tier‑3 monitor mode** (optional, needs an external adapter — see below):
  - **Deauth / disassoc attack detection** (rate + reason code)
  - **Evil‑twin** detection (same SSID, multiple BSSIDs)
  - **Connected‑client count** per AP, drawn as anonymous dots in a mesh view
    (router + repeaters). No client identities are shown or stored — see below.
- **LAN device list** (ARP) for your own connected network.

This build **stores nothing**: there is no data export, and the monitor snapshot
is a volatile file in RAM that is overwritten every few seconds and deleted when
monitoring stops.

---

## Building & installing the app

You need the **Sailfish OS SDK** (the `mb2` build tool and a target, e.g.
`SailfishOS-5.0.0.62-aarch64`).

```sh
# from the project root
mb2 -t SailfishOS-5.0.0.62-aarch64 build
# install the resulting package on the device (as root)
scp RPMS/harbour-iwifi-*.aarch64.rpm root@<device-ip>:/tmp/
ssh root@<device-ip> 'rpm -Uvh --force /tmp/harbour-iwifi-*.aarch64.rpm'
```

The package bundles the monitor‑mode pieces (sniffer, systemd unit, polkit rule);
they stay dormant until you enable **Monitor mode** in the radar pulley menu, and
they only run while the app is in the foreground.

---

## Tier‑3: external antenna + monitor‑mode driver (the hard part)

Real Wi‑Fi monitor mode is what lets the app *see* deauth attacks and connected
clients. This is the difficult part of the project, so it is documented in full.

### Why an external adapter

The Xperia 10 III's internal Qualcomm chip **advertises** a `monitor` mode but it
is **non‑functional**: a `mon0` interface comes up `NO‑CARRIER` and captures **0
frames**. You therefore need an external USB adapter that genuinely supports
monitor mode.

### The adapter

A **Realtek RTL8812AU** adapter (e.g. an Alfa AWUS036ACH, USB id `0bda:8812`).
Sailfish's stock kernel has **no driver** for it, so you must build one. The
driver to use is **`morrownr/8812au-20210820`**, because it exposes a
`CONFIG_WIFI_MONITOR` switch that adds `NL80211_IFTYPE_MONITOR` to the wiphy.

### Why you must build against the exact kernel

The Xperia 10 III kernel is built with **`CONFIG_MODVERSIONS=y`**. A loadable
module must carry symbol CRCs that match the running kernel, so you need the
**matching kernel source and the device's exact `.config`** to generate a correct
`Module.symvers`. `MODULE_SIG_FORCE` is **off**, so an unsigned `.ko` loads fine;
the build has no LTO/CFI, so the ABI is standard.

### Sources you need (and why exactly these)

| What | Where | Why this one |
|------|-------|--------------|
| Kernel source | `github.com/sonyxperiadev/kernel`, branch **`aosp/LA.UM.9.12.r1`** | The real Linux 4.19.248 source for `pdx213`; has `arch/arm64/configs/aosp_lena_pdx213_defconfig`. (`kernel-sony-msm-4.19-common` is only build *scripts*, not source.) |
| Device `.config` | `zcat /proc/config.gz` **from your device** | Exactly the config of the running kernel → matching symbol CRCs. |
| Clang | AOSP prebuilt **`clang-r353983c`** (clang 9.0.3) | The toolchain the kernel was built with; needed to link `vmlinux`. |
| binutils | AOSP **`aarch64-linux-android-4.9`** GNU binutils | clang‑9's integrated assembler/linker can't handle the 4.19 arm64 asm; use GNU `as`/`ld` instead. |
| Driver | **`morrownr/8812au-20210820`** | Has the `CONFIG_WIFI_MONITOR` switch. |

### Step 1 — kernel source + config

```sh
git clone -b aosp/LA.UM.9.12.r1 https://github.com/sonyxperiadev/kernel
mkdir out
# pull the running config off the device and use it verbatim
ssh root@<device-ip> 'zcat /proc/config.gz' > out/.config
```

### Step 2 — toolchain on PATH

Fetch the AOSP prebuilt clang `clang-r353983c` and the
`aarch64-linux-android-4.9` GNU binutils, then:

```sh
export PATH="$PWD/clang-r353983c/bin:$PWD/binutils/bin:$PATH"
```

### Step 3 — build `vmlinux` (to get `Module.symvers`)

```sh
make -C kernel O=$PWD/out ARCH=arm64 \
     CC=clang CLANG_TRIPLE=aarch64-linux-gnu- CROSS_COMPILE=aarch64-linux-android- \
     olddefconfig vmlinux -j"$(nproc)"
```

Use **`CC=clang` + GNU binutils** — do **not** pass `LLVM=1 LLVM_IAS=1`.

Patches needed to get `vmlinux` to link (none of them affect the cfg80211/usb
CRCs the driver depends on):

- remove `-n` from `arch/arm64/kernel/vdso/Makefile`;
- disable `CONFIG_COMPAT_VDSO`;
- create empty stub `Makefile` + `Kbuild` for the separate‑repo dirs that aren't
  present: `drivers/staging/wlan-qc/{qcacld-3.0,qca-wifi-host-cmn,fw-api}` and
  `techpack/{audio,display,video,camera,data}`.

### Step 4 — build the driver

In the `8812au-20210820` tree, set **`CONFIG_WIFI_MONITOR = y`** (Makefile, around
line 112 — it defaults to `n`; this is *the* switch) and add
`EXTRA_CFLAGS += -Wno-unknown-warning-option` (clang‑9 rejects newer GCC `-Wno-*`
flags under `-Werror`). Then:

```sh
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-android- \
     CC=clang CLANG_TRIPLE=aarch64-linux-gnu- \
     KSRC=$PWD/../out KVER=4.19.248 -j"$(nproc)" modules
```

### Step 5 — install + enable monitor mode

```sh
scp 8812au.ko root@<device-ip>:/tmp/
ssh root@<device-ip>
  insmod /tmp/8812au.ko            # wlan1 appears (Realtek 00:c0:ca:…)
  ip link set wlan1 down
  iw dev wlan1 set type monitor
  ip link set wlan1 up
  iw dev wlan1 set channel 6       # capture starts
```

To make the module persistent across reboots:

```sh
install -D 8812au.ko /lib/modules/4.19.248/extra/8812au.ko
depmod 4.19.248                    # udev then autoloads it on hotplug
```

The app's bundled `harbour-iwifi-monitor.service` does the `modprobe` + monitor
setup for you when you enable **Monitor mode**; the manual steps above are for
first‑time bring‑up and debugging.

### Troubleshooting (errors you are likely to hit)

- **`ld.lld: error: unknown argument: -n`** (VDSO) → remove `-n` from
  `arch/arm64/kernel/vdso/Makefile`.
- **`-z common-page-size`** (vdso32) → disable `CONFIG_COMPAT_VDSO`.
- **`llvm-ar: unknown option 'P'`** or assembler errors on `head.S` → you're using
  the integrated LLVM tools; switch to `CC=clang` + GNU binutils (drop `LLVM=1
  LLVM_IAS=1`).
- **clang‑9 `unknown warning option`** under `-Werror` → add
  `EXTRA_CFLAGS += -Wno-unknown-warning-option` to the driver Makefile.
- **adapter loads but monitor isn't offered** → `CONFIG_WIFI_MONITOR` wasn't set
  to `y`.
- **`.ko` vermagic has a `-dirty` suffix** → it still loads; MODVERSIONS matches by
  CRC and signing isn't enforced.
- **battery drains fast** → continuous monitor capture is power‑hungry; the app
  app‑gates the sniffer (foreground only) for exactly this reason.

---

## Status & responsible use

**Proof of concept / work in progress.** This is a hobby project, shared **as is**
with **no warranty** of any kind (see the GPLv3). It may be incomplete, rough
around the edges, or change without notice — use it at your own risk.

iWifi is a **passive analysis / defensive** tool. It does not transmit, attack,
crack, or decrypt anything. Even so, **how you use it is your responsibility**:

- Monitor mode receives 802.11 management/control frames. Use it on **your own
  network**, or where you have **permission**.
- A Wi‑Fi client's MAC address can identify a device, so this build avoids
  retaining it: the sniffer counts associated clients but **emits no MAC
  addresses, no probe‑request lists and no per‑device data**; the UI shows clients
  only as **anonymous dots by count**. Nothing is written to disk and there is no
  export.

Use it to understand and harden your own Wi‑Fi.

---

AI assisted development

## License & attribution

Licensed under the **GNU General Public License v3 or later**. See `LICENSE`.

The bundled MAC‑vendor database (`data/oui.tsv`) is derived from the Wireshark
`manuf` list (GPLv2‑compatible). See `THIRD-PARTY-NOTICES.md`.
