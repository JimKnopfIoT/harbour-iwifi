/*
  harbour-iwifi — iwsniff: 802.11 monitor-mode sniffer (root helper, Tier 3)
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  PRIVACY-MINIMISED build. Captures raw 802.11 frames from a monitor-mode
  interface (e.g. wlan1 on an RTL8812AU), channel-hops, and extracts ONLY:
    - APs from beacons (BSSID, SSID, channel, signal, beacon count)
    - per-AP attack indicators: deauth/disassoc rate + reason (defensive),
      and same-SSID sibling count (evil-twin hint)
    - per-AP COUNT of associated Wi-Fi clients (an integer)

  It deliberately does NOT emit, store or profile individual clients: no client
  MAC addresses, no probe-request SSIDs (preferred-network list), no per-device
  traffic / OS / vendor / capabilities. Client MACs are held only transiently in
  RAM to deduplicate the count and are never written out. Output is a JSON
  snapshot rewritten every few seconds (mode "w", overwritten, no history) which
  the sandboxed UI reads. The interface must already be `type monitor` + up.

  Build (SailfishOS SDK aarch64). Run as root:
    iwsniff wlan1 /tmp/iwifi-sniff.json
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <linux/if_ether.h>

#define MAX_AP   512
#define MAX_STA 1024
#define SNAP_INTERVAL 3      /* seconds between JSON snapshots */
#define HOP_MS 280           /* dwell time per channel */
#define AGE_SECS 120         /* drop entries unseen for this long */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

static volatile int g_run = 1;
static void on_sig(int s) { (void)s; g_run = 0; }

/* ---- channel hop set: 2.4 GHz then common 5 GHz ---- */
static const int channels[] = {
    1, 6, 11, 2, 3, 4, 5, 7, 8, 9, 10, 12, 13,
    36, 40, 44, 48, 149, 153, 157, 161, 165
};
static const int n_channels = sizeof(channels) / sizeof(channels[0]);

typedef struct {
    u8 bssid[6];
    char ssid[33];
    int channel;
    int signal;          /* dBm, 0 = unknown */
    time_t last;
    int beacons;
    /* attack detection (defensive; no per-client data) */
    int deauths;         /* total deauth frames naming this BSSID */
    int disassocs;       /* total disassoc frames naming this BSSID */
    int prev_deauth;     /* deauths+disassocs at last snapshot */
    int deauth_rate;     /* (deauth+disassoc) per snapshot interval */
    int reason;          /* last deauth/disassoc reason code */
    int attack_sig;      /* dBm of the last deauth/disassoc frame (attacker TX) */
    u8  attacker[6];     /* transmitter addr2 of last deauth (often spoofed = bssid) */
    u8  target[6];       /* destination addr1 of last deauth (victim / broadcast) */
} Ap;

/* A client is tracked ONLY to count it. Its MAC lives here transiently (for
   dedup + aging) and is never written to the JSON. No profiling fields. */
typedef struct {
    u8 mac[6];
    u8 bssid[6];         /* AP it is associated with */
    time_t last;
} Sta;

static Ap  aps[MAX_AP];   static int n_ap = 0;
static Sta stas[MAX_STA]; static int n_sta = 0;

static int mac_zero(const u8 *m) {
    return !(m[0]|m[1]|m[2]|m[3]|m[4]|m[5]);
}
static int mac_mcast(const u8 *m) { return m[0] & 0x01; } /* incl. broadcast */

static Ap *find_ap(const u8 *b) {
    int i; for (i = 0; i < n_ap; i++) if (!memcmp(aps[i].bssid, b, 6)) return &aps[i];
    if (n_ap >= MAX_AP) return NULL;
    Ap *a = &aps[n_ap++]; memset(a, 0, sizeof(*a)); memcpy(a->bssid, b, 6); return a;
}
/* Record an associated client (for counting only). */
static void note_client(const u8 *mac, const u8 *bssid, time_t now) {
    int i;
    if (mac_mcast(mac) || mac_zero(mac)) return;
    for (i = 0; i < n_sta; i++)
        if (!memcmp(stas[i].mac, mac, 6)) {
            memcpy(stas[i].bssid, bssid, 6);
            stas[i].last = now;
            return;
        }
    if (n_sta >= MAX_STA) return;
    Sta *s = &stas[n_sta++]; memset(s, 0, sizeof(*s));
    memcpy(s->mac, mac, 6); memcpy(s->bssid, bssid, 6); s->last = now;
}

static int g_channel = 0;          /* channel currently dwelled on */
#define LOCK_SECS 6                /* dwell time after a deauth (catch the flood) */
static time_t g_lock_until = 0;    /* while now < this: pause channel-hopping */

/* ---- minimal radiotap parser: returns header length, fills *sig (dBm) ---- */
static int radiotap_parse(const u8 *buf, int len, int *sig) {
    if (len < 8) return -1;
    if (buf[0] != 0) return -1;                 /* version 0 */
    int it_len = buf[2] | (buf[3] << 8);
    if (it_len < 8 || it_len > len) return -1;

    u32 present = buf[4] | (buf[5]<<8) | (buf[6]<<16) | (buf[7]<<24);
    int off = 8;
    /* skip any extended present bitmaps (bit 31 chains) */
    while (present & (1u << 31)) {
        if (off + 4 > it_len) break;
        present = buf[off] | (buf[off+1]<<8) | (buf[off+2]<<16) | (buf[off+3]<<24);
        off += 4;
    }
    /* walk the standard early fields in order, honouring alignment, until we
       reach DBM_ANTSIGNAL (bit 5). */
    static const int fsize[6] = { 8, 1, 1, 4, 2, 1 };
    static const int falign[6] = { 8, 1, 1, 2, 2, 1 };
    u32 first = buf[4] | (buf[5]<<8) | (buf[6]<<16) | (buf[7]<<24);
    int b;
    for (b = 0; b <= 5; b++) {
        if (!(first & (1u << b))) continue;
        int a = falign[b];
        off = (off + (a - 1)) & ~(a - 1);
        if (b == 5) {
            if (off < it_len) *sig = (signed char)buf[off];
            return it_len;
        }
        off += fsize[b];
        if (off > it_len) break;
    }
    return it_len;
}

/* ---- 802.11 parse ---- */
static void handle_frame(const u8 *f, int len, int sig) {
    if (len < 24) return;
    u16 fc = f[0] | (f[1] << 8);
    int type = (fc >> 2) & 3;
    int subtype = (fc >> 4) & 0xf;
    int tods = (fc >> 8) & 1, fromds = (fc >> 9) & 1;
    time_t now = time(NULL);

    const u8 *a1 = f + 4, *a2 = f + 10, *a3 = f + 16;

    if (type == 0) {                                   /* management */
        if (subtype == 8 || subtype == 5) {            /* beacon / probe-resp */
            Ap *ap = find_ap(a3);                      /* BSSID = addr3 */
            if (!ap) return;
            ap->last = now; ap->beacons++;
            if (sig) ap->signal = sig;
            int p = 36;                                /* tagged params */
            while (p + 2 <= len) {
                int tag = f[p], tl = f[p+1];
                if (p + 2 + tl > len) break;
                if (tag == 0 && tl <= 32) {            /* SSID */
                    memcpy(ap->ssid, f + p + 2, tl); ap->ssid[tl] = 0;
                } else if (tag == 3 && tl >= 1) {      /* DS param = channel */
                    ap->channel = f[p+2];
                }
                p += 2 + tl;
            }
        } else if (subtype == 0 || subtype == 2) {     /* (re)assoc request */
            /* addr2 = STA, addr1 = AP. Count it as a client; do not profile. */
            note_client(a2, a1, now);
        } else if (subtype == 12 || subtype == 10) {   /* DEAUTH / DISASSOC */
            Ap *ap = find_ap(a3);                       /* BSSID named in frame */
            if (!ap) return;
            ap->last = now;
            if (subtype == 12) ap->deauths++; else ap->disassocs++;
            if (len >= 26) ap->reason = f[24] | (f[25] << 8);
            if (sig && !ap->signal) ap->signal = sig;
            if (sig) ap->attack_sig = sig;             /* RSSI of the ATTACKER's TX */
            memcpy(ap->attacker, a2, 6);               /* sender (often spoofed = bssid) */
            memcpy(ap->target, a1, 6);                 /* victim client / broadcast */
            /* Lock onto this channel so the channel-hopper stops skipping the
               attack and we actually accumulate the rate + a stable RSSI. */
            g_lock_until = now + LOCK_SECS;
        }
        /* NOTE: probe requests (subtype 4) are intentionally ignored — we never
           collect which networks a device is looking for (preferred-network
           list = device tracking). */
        return;
    }

    if (type == 2) {                                   /* data */
        const u8 *bssid, *sta;
        if (!tods && fromds)      { bssid = a2; sta = a1; }   /* AP -> STA */
        else if (tods && !fromds) { bssid = a1; sta = a2; }   /* STA -> AP */
        else return;                                          /* IBSS / WDS: skip */
        find_ap(bssid);                                       /* note the BSSID */
        note_client(sta, bssid, now);                         /* count, no profile */
    }
}

static void age_out(time_t now) {
    int i;
    for (i = 0; i < n_sta; ) {
        if (now - stas[i].last > AGE_SECS) stas[i] = stas[--n_sta];
        else i++;
    }
    for (i = 0; i < n_ap; ) {
        if (now - aps[i].last > AGE_SECS) aps[i] = aps[--n_ap];
        else i++;
    }
}

static void jmac(FILE *fp, const u8 *m) {
    fprintf(fp, "\"%02X:%02X:%02X:%02X:%02X:%02X\"",
            m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* JSON-escape an SSID (may hold quotes, backslashes, control or non-ASCII bytes) */
static void jstr(FILE *fp, const char *s) {
    fputc('"', fp);
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') { fputc('\\', fp); fputc(c, fp); p++; }
        else if (c < 0x20) { fprintf(fp, "\\u%04x", c); p++; }
        else if (c < 0x80) { fputc(c, fp); p++; }
        else {
            int n = (c >= 0xF0) ? 4 : (c >= 0xE0) ? 3 : (c >= 0xC0) ? 2 : 0, k, ok = (n > 0);
            for (k = 1; k < n && ok; k++) if ((p[k] & 0xC0) != 0x80) ok = 0;
            if (ok) { for (k = 0; k < n; k++) fputc(p[k], fp); p += n; }
            else { fprintf(fp, "\\u%04x", c); p++; }
        }
    }
    fputc('"', fp);
}

/* per-snapshot deauth/disassoc rate (attack indicator) */
static void update_rates(void) {
    int i;
    for (i = 0; i < n_ap; i++) {
        int total = aps[i].deauths + aps[i].disassocs;
        aps[i].deauth_rate = total - aps[i].prev_deauth;
        aps[i].prev_deauth = total;
    }
}

/* number of associated clients currently counted for a BSSID */
static int client_count(const u8 *bssid) {
    int i, c = 0;
    for (i = 0; i < n_sta; i++)
        if (!memcmp(stas[i].bssid, bssid, 6)) c++;
    return c;
}

static void write_json(const char *path) {
    char tmp[512]; snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *fp = fopen(tmp, "w"); if (!fp) return;
    time_t now = time(NULL);
    fprintf(fp, "{\"ts\":%ld,\"aps\":[", (long)now);
    int i, first = 1;
    for (i = 0; i < n_ap; i++) {
        if (!first) fputc(',', fp); first = 0;
        int sib = 0, j;                            /* same-SSID siblings (evil twin) */
        if (aps[i].ssid[0])
            for (j = 0; j < n_ap; j++)
                if (j != i && !strcmp(aps[j].ssid, aps[i].ssid)) sib++;
        int attack = aps[i].deauth_rate >= 5;      /* >~1.6 deauth/s sustained */
        fprintf(fp, "{\"bssid\":"); jmac(fp, aps[i].bssid);
        fprintf(fp, ",\"ssid\":"); jstr(fp, aps[i].ssid);
        fprintf(fp, ",\"channel\":%d,\"signal\":%d,\"beacons\":%d,"
                    "\"deauths\":%d,\"disassocs\":%d,\"deauthRate\":%d,\"reason\":%d,"
                    "\"attack\":%s,\"attackSig\":%d,\"siblings\":%d,\"clients\":%d,\"attacker\":",
                aps[i].channel, aps[i].signal, aps[i].beacons,
                aps[i].deauths, aps[i].disassocs, aps[i].deauth_rate, aps[i].reason,
                attack ? "true" : "false", aps[i].attack_sig, sib, client_count(aps[i].bssid));
        jmac(fp, aps[i].attacker);
        fprintf(fp, ",\"target\":"); jmac(fp, aps[i].target);
        fputc('}', fp);
    }
    /* No per-client objects are emitted — clients appear only as a per-AP count. */
    fprintf(fp, "]}\n");
    fclose(fp);
    rename(tmp, path);
}

static void set_channel(const char *iface, int ch) {
    g_channel = ch;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d >/dev/null 2>&1", iface, ch);
    if (system(cmd) != 0) { /* 5GHz may need HT/period; ignore failures */ }
}

int main(int argc, char **argv) {
    const char *iface = argc > 1 ? argv[1] : "wlan1";
    const char *out   = argc > 2 ? argv[2] : "/tmp/iwifi-sniff.json";

    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket"); return 1; }
    int ifindex = if_nametoindex(iface);
    if (!ifindex) { fprintf(stderr, "no interface %s\n", iface); return 1; }
    struct sockaddr_ll sll; memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET; sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) { perror("bind"); return 1; }

    fprintf(stderr, "iwsniff on %s -> %s\n", iface, out);
    u8 buf[4096];
    int chi = 0;
    set_channel(iface, channels[chi]);
    struct timespec t_hop, t_snap; clock_gettime(CLOCK_MONOTONIC, &t_hop); t_snap = t_hop;

    while (g_run) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, 60);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            int n = recv(fd, buf, sizeof(buf), 0);
            if (n > 0) {
                int sig = 0;
                int rtlen = radiotap_parse(buf, n, &sig);
                if (rtlen > 0 && rtlen < n)
                    handle_frame(buf + rtlen, n - rtlen, sig);
            }
        }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        long hop_ms = (now.tv_sec - t_hop.tv_sec) * 1000 +
                      (now.tv_nsec - t_hop.tv_nsec) / 1000000;
        if (hop_ms >= HOP_MS) {
            if (time(NULL) < g_lock_until) {
                t_hop = now;          /* locked onto an active attack — hold channel */
            } else {
                chi = (chi + 1) % n_channels;
                set_channel(iface, channels[chi]);
                t_hop = now;
            }
        }
        if (now.tv_sec - t_snap.tv_sec >= SNAP_INTERVAL) {
            age_out(time(NULL));
            update_rates();
            write_json(out);
            t_snap = now;
        }
    }
    write_json(out);
    close(fd);
    return 0;
}
