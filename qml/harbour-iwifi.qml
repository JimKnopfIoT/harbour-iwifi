

/*
  Copyright (C) 2015 Petr Vytovtov
  Contact: Petr Vytovtov <iwifi@protonmail.ch>
  All rights reserved.

  This file is part of WiFi Analyser for Sailfish OS.

  WiFi Analyser is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  WiFi Analyser is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with WiFi Analyser.  If not, see <http://www.gnu.org/licenses/>.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0
import Connman 0.2
import QtPositioning 5.0

import "pages"

ApplicationWindow {
    id: rootApp

    allowedOrientations: defaultAllowedOrientations
    _defaultPageOrientations: defaultAllowedOrientations

    property string frequencyBand: "2.4GHz"


    /**
     * The method calculates the WiFi-network channel.
     * @param frequency - the frequency of current WiFi-network
     * @return The channel number of current WiFi-network
     */
    function calculateChannel(frequency) {
        switch (frequency) {
        case 2412:
            return 0
        case 2417:
            return 1
        case 2422:
            return 2
        case 2427:
            return 3
        case 2432:
            return 4
        case 2437:
            return 5
        case 2442:
            return 6
        case 2447:
            return 7
        case 2452:
            return 8
        case 2457:
            return 9
        case 2462:
            return 10
        case 2467:
            return 11
        case 2472:
            return 12
        case 2484:
            return 13
            // 5GHz
        case 5035:
            return 6
        case 5040:
            return 7
        case 5045:
            return 8
        case 5055:
            return 10
        case 5060:
            return 11
        case 5080:
            return 15
        case 5160:
            return 31
        case 5170:
            return 33
        case 5180:
            return 35
        case 5190:
            return 37
        case 5200:
            return 39
        case 5210:
            return 41
        case 5220:
            return 43
        case 5230:
            return 45
        case 5240:
            return 47
        case 5250:
            return 49
        case 5260:
            return 51
        case 5270:
            return 53
        case 5280:
            return 55
        case 5290:
            return 57
        case 5300:
            return 59
        case 5310:
            return 61
        case 5320:
            return 63
        case 5340:
            return 67
        case 5480:
            return 95
        case 5500:
            return 99
        case 5510:
            return 101
        case 5520:
            return 103
        case 5530:
            return 105
        case 5540:
            return 107
        case 5550:
            return 109
        case 5560:
            return 111
        case 5570:
            return 113
        case 5580:
            return 115
        case 5590:
            return 117
        case 5600:
            return 119
        case 5610:
            return 121
        case 5620:
            return 123
        case 5630:
            return 125
        case 5640:
            return 127
        case 5660:
            return 131
        case 5670:
            return 133
        case 5680:
            return 135
        case 5690:
            return 137
        case 5700:
            return 139
        case 5710:
            return 141
        case 5720:
            return 143
        case 5745:
            return 148
        case 5755:
            return 150
        case 5765:
            return 152
        case 5775:
            return 154
        case 5785:
            return 156
        case 5795:
            return 158
        case 5805:
            return 160
        case 5825:
            return 164
        case 5845:
            return 168
        case 5865:
            return 172
        case 4915:
            return 182
        case 4920:
            return 183
        case 4925:
            return 184
        case 4935:
            return 186
        case 4940:
            return 187
        case 4945:
            return 188
        case 4960:
            return 191
        case 4980:
            return 195
        default:
            return -1
            // default: return -1;
        }
    }

    // Measured rough bearings (deg from magnetic north) per BSSID, filled by the
    // direction finder and consumed by the radar view. Persisted to a DB later.
    property var apBearings: ({})

    function setBearing(bssid, deg) {
        var m = apBearings
        m[bssid] = deg
        apBearings = m // reassign so bindings update
    }

    /**
     * Build an enriched plain-object snapshot of a ConnMan NetworkService,
     * shared by the list view and the graph tap handler so both push an
     * identical object into DetailPage.
     */
    function enrichService(s) {
        var dbm = s.strength - 120
        var sec = iw.classifySecurity(s.security)
        return {
            "name": s.name,
            "bssid": s.bssid,
            "frequency": s.frequency,
            "strength": s.strength,
            "dbm": dbm,
            "security": s.security,
            "vendor": iw.vendor(s.bssid),
            "laa": iw.isLocallyAdministered(s.bssid),
            "band": iw.band(s.frequency),
            "channel": iw.channel(s.frequency),
            "distance": iw.distanceMeters(dbm, s.frequency),
            "secLabel": sec.label,
            "secColor": sec.color,
            "secRisk": sec.risk,
            "wps": sec.wps,
            "isWpa3": sec.isWpa3
        }
    }

    function riskColor(risk) {
        if (risk === "good") return "#4CAF50"
        if (risk === "ok") return "#8BC34A"
        if (risk === "weak") return "#FF9800"
        return "#F44336"
    }

    /**
     * Enrich a per-BSS record from `iwscan` (iw scan dump) with vendor/distance/
     * band/channel/colour. iwscan already provides the rich fields ConnMan hides
     * (separate BSSes, WPS model, channel width, real dBm, RSN-based security).
     */
    function enrichScan(r) {
        return {
            "name": r.ssid,
            "bssid": r.bssid,
            "frequency": r.frequency,
            "strength": r.strength,
            "dbm": r.signal,
            "security": [r.security],
            "secLabel": r.security,
            "secColor": riskColor(r.secRisk),
            "secRisk": r.secRisk,
            "isWpa3": r.isWpa3,
            "wps": r.wps,
            "vendor": iw.vendor(r.bssid),
            "laa": iw.isLocallyAdministered(r.bssid),
            "band": iw.band(r.frequency),
            "channel": iw.channel(r.frequency),
            "distance": iw.distanceMeters(r.signal, r.frequency),
            "chWidth": r.chWidth,
            "phy": r.phy,
            "manufacturer": r.manufacturer,
            "model": r.model,
            "deviceName": r.deviceName,
            "serial": r.serial,
            "cipher": r.cipher,
            "pmf": r.pmf,
            "country": r.country,
            "hidden": r.hidden,
            "bssStations": r.bssStations,
            "bssUtil": r.bssUtil
        }
    }

    // rough channel -> centre frequency (for synthetic attacker entries)
    function channelToFreq(ch) {
        if (ch >= 1 && ch <= 13) return 2407 + ch * 5
        if (ch === 14) return 2484
        if (ch >= 36) return 5000 + ch * 5
        return 2412
    }

    /**
     * Synthetic "device" entries for every AP the monitor sniffer currently sees
     * under a deauth/disassoc attack. The ATTACKER (the transmitter of the deauth
     * frames) is not a beaconing AP, so it never shows up in the normal scan. We
     * surface it as its own orange ☠ entry, placed by the RSSI of its attack
     * frames (attackSig) so it can be located by walking hot/cold. If the attacker
     * spoofs the AP's BSSID the MAC matches the victim, but the attack RSSI still
     * differs from the real AP's beacon RSSI. Display only — nothing is logged.
     */
    function attackerEntries() {
        var out = []
        if (!sniffer.available) return out
        var aps = sniffer.aps
        for (var i = 0; i < aps.length; ++i) {
            var m = aps[i]
            if (!m.attack) continue
            var freq = channelToFreq(m.channel)
            var sigv = (m.attackSig && m.attackSig < 0) ? m.attackSig
                       : (m.signal && m.signal < 0 ? m.signal : -60)
            var pct = Math.max(0, Math.min(100, Math.round(2 * (sigv + 100))))
            out.push({
                "name": "☠ Deauth-Attacker",
                "bssid": (m.attacker && m.attacker.length) ? m.attacker : m.bssid,
                "frequency": freq,
                "channel": m.channel,
                "band": iw.band(freq),
                "dbm": sigv,
                "strength": pct,
                "secLabel": "☠ Deauth-Attacker",
                "secColor": "#FF6D00",
                "secRisk": "bad",
                "wps": false,
                "isWpa3": false,
                "vendor": iw.vendor((m.attacker && m.attacker.length) ? m.attacker : m.bssid),
                "laa": iw.isLocallyAdministered((m.attacker && m.attacker.length) ? m.attacker : m.bssid),
                "distance": iw.distanceMeters(sigv, freq),
                // attack metadata (read by the radar skull + detail page)
                "attack": true,
                "attackSig": m.attackSig || 0,
                "attacker": m.attacker || "",
                "attackTarget": m.target || "",
                "victimBssid": m.bssid,
                "victimSsid": m.ssid,
                "deauthRate": m.deauthRate || 0,
                "attackReason": m.reason || 0
            })
        }
        return out
    }

    // NOTE: this build deliberately has NO data export. The app only ever
    // displays the live state and never writes scan/client data to disk.

    property string toastMsg: ""
    function showToast(m) { toastMsg = m; toastTimer.restart() }

    // --- Monitor mode (Tier 3 — external RTL8812AU adapter; opt-in) ---
    // App-gated: the root sniffer (harbour-iwifi-monitor.service) runs ONLY
    // while the app is in the foreground and is stopped on background/exit, so
    // the battery-draining monitor capture never runs unattended. The user
    // opts in once (persisted); after that it auto-(re)starts with the app.
    property bool monitorEnabled: settings.value("monitorEnabled") === "true"
    function setMonitor(on) {
        monitorEnabled = on
        settings.setValue("monitorEnabled", on ? "true" : "false")
        if (on) {
            monitor.start()
            showToast(qsTr("Monitor mode on — needs the external adapter plugged in"))
        } else {
            monitor.stop()
            showToast(qsTr("Monitor mode off"))
        }
    }

    // --- GPS (opt-in; off by default for privacy + power) ---
    // Always starts OFF and is switched off when the app leaves the foreground,
    // so GPS is never silently left running between sessions.
    property bool gpsEnabled: false
    property real gpsLat: 0
    property real gpsLon: 0
    property real gpsAcc: -1
    property bool gpsValid: false
    function setGps(on) {
        gpsEnabled = on
        if (!on) gpsValid = false
        showToast(on ? qsTr("GPS on — scans get tagged with location")
                     : qsTr("GPS off"))
    }
    PositionSource {
        id: gps
        active: rootApp.gpsEnabled
        // prefer real satellite GNSS over the network/cell fix — the latter is
        // what gives the coarse ~±10 m position; pure GNSS converges to a few m.
        preferredPositioningMethods: PositionSource.SatellitePositioningMethods
        updateInterval: 1000   // update often so the GNSS fix converges quickly
        onPositionChanged: {
            if (position.latitudeValid && position.longitudeValid) {
                var acc = position.horizontalAccuracyValid
                        ? position.horizontalAccuracy : -1
                // keep the better fix: while standing still GNSS accuracy keeps
                // improving, so don't let an occasional worse sample bounce the
                // marker around. Always accept if we have no fix yet, if the new
                // one is at least as good, or if we've clearly moved (>15 m).
                var moved = rootApp.gpsValid
                        ? rootApp.distMeters(rootApp.gpsLat, rootApp.gpsLon,
                                             position.coordinate.latitude,
                                             position.coordinate.longitude) > 15
                        : true
                if (!rootApp.gpsValid || moved || acc < 0 || rootApp.gpsAcc < 0
                        || acc <= rootApp.gpsAcc + 1) {
                    rootApp.gpsLat = position.coordinate.latitude
                    rootApp.gpsLon = position.coordinate.longitude
                    rootApp.gpsAcc = acc
                    rootApp.gpsValid = true
                }
            }
        }
    }
    // metres between two lat/lon points (equirectangular — fine at these scales)
    function distMeters(la1, lo1, la2, lo2) {
        var dN = (la2 - la1) * 111320
        var dE = (lo2 - lo1) * 111320 * Math.cos(la1 * Math.PI / 180)
        return Math.sqrt(dN * dN + dE * dE)
    }

    Component.onCompleted: {
        iwscan.start()
        // resume monitor capture on launch if the user opted in earlier
        if (monitorEnabled) monitor.start()
    }

    Connections {
        target: Qt.application
        onStateChanged: {
            if (Qt.application.state === Qt.ApplicationActive) {
                updateTimer.running = true
                iwscan.start()
                if (monitorEnabled) monitor.start()
            } else {
                updateTimer.running = false
                iwscan.stop()
                // drop GPS (and with it the map) when backgrounded/closed
                gpsEnabled = false
                gpsValid = false
                // stop the battery-draining sniffer whenever we leave the front
                monitor.stop()
            }
        }
    }

    // Radar is always the entry page. Swipe right → network list → tap a
    // network → detail → swipe right → connected-client map.
    initialPage: Qt.resolvedUrl("pages/RadarPage.qml")
    cover: Qt.resolvedUrl("cover/CoverPage.qml")

    Timer {
        id: updateTimer
        interval: 2000
        running: true
        repeat: true
        triggeredOnStart: true

        onTriggered: networksList.requestScan()
    }

    // More info:
    // https://git.merproject.org/mer-core/libconnman-qt/blob/master/plugin/technologymodel.h
    // https://git.merproject.org/mer-core/libconnman-qt/blob/master/libconnman-qt/networkservice.h
    TechnologyModel {
        id: networksList
        name: "wifi"
    }

    Timer { id: toastTimer; interval: 4500; onTriggered: rootApp.toastMsg = "" }

    Rectangle {
        z: 1000
        visible: rootApp.toastMsg.length > 0
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: toastLbl.height + 2 * Theme.paddingLarge
        color: Theme.rgba(Theme.highlightDimmerColor, 0.95)
        Label {
            id: toastLbl
            anchors { left: parent.left; right: parent.right
                      verticalCenter: parent.verticalCenter
                      leftMargin: Theme.horizontalPageMargin
                      rightMargin: Theme.horizontalPageMargin }
            wrapMode: Text.WrapAnywhere
            font.pixelSize: Theme.fontSizeExtraSmall
            color: Theme.highlightColor
            text: rootApp.toastMsg
        }
        MouseArea { anchors.fill: parent; onClicked: rootApp.toastMsg = "" }
    }

    // --- Persistent battery indicator (top-left, on every page) ---
    // The external monitor adapter drains the phone fast, so the level must be
    // visible at all times to avoid running flat.
    Row {
        id: batteryIndicator
        z: 1000
        spacing: Theme.paddingSmall / 2
        anchors {
            left: parent.left
            top: parent.top
            leftMargin: Theme.paddingMedium
            topMargin: Theme.paddingSmall
        }
        property int lvl: battery.level
        // green > 50 %, gold ≤ 50 %, orange ≤ 30 %, red ≤ 10 %, dim grey if unknown
        property color lvlColor: lvl < 0 ? Theme.rgba(Theme.primaryColor, 0.4)
                                : lvl <= 10 ? "#F44336"
                                : lvl <= 30 ? "#FF9800"
                                : lvl <= 50 ? "#FFD700"
                                : "#4CAF50"

        // battery body
        Item {
            width: Theme.iconSizeSmall * 0.9
            height: Theme.iconSizeSmall * 0.5
            anchors.verticalCenter: parent.verticalCenter

            Rectangle {  // outline
                id: batBody
                anchors.fill: parent
                radius: 2
                color: "transparent"
                border.color: Theme.rgba(Theme.primaryColor, 0.7)
                border.width: 1
            }
            Rectangle {  // fill
                anchors {
                    left: batBody.left; top: batBody.top; bottom: batBody.bottom
                    margins: 2
                }
                width: Math.max(1, (batBody.width - 4)
                                * (batteryIndicator.lvl < 0 ? 0
                                   : batteryIndicator.lvl / 100))
                radius: 1
                color: batteryIndicator.lvlColor
            }
            Rectangle {  // cap
                anchors { left: batBody.right; verticalCenter: batBody.verticalCenter }
                width: 2
                height: parent.height * 0.4
                color: Theme.rgba(Theme.primaryColor, 0.7)
            }
            // charging bolt
            Label {
                anchors.centerIn: batBody
                visible: battery.charging
                text: "⚡"
                font.pixelSize: parent.height * 0.9
                color: Theme.primaryColor
            }
        }

        Label {
            anchors.verticalCenter: parent.verticalCenter
            text: batteryIndicator.lvl < 0 ? "—" : batteryIndicator.lvl + "%"
            font.pixelSize: Theme.fontSizeExtraSmall
            color: batteryIndicator.lvlColor
        }
    }
}
