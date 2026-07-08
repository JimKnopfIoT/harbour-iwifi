/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Single-hotspot detail view. Shows every datum obtainable on-device (Tier 1).
  Fields that require the connected network (Tier 2) or monitor mode (Tier 3)
  are shown as "n/a" until those tiers land.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

import "../views"

Page {
    id: detailPage

    property var ap

    // measured bearing of this AP (deg from North), set by tapping "Set
    // direction" while facing it; shared with the radar via apBearings.
    property real myBearing: (ap && apBearings[ap.bssid] !== undefined)
                             ? apBearings[ap.bssid] : -1

    // Tier-3 monitor-mode data for this AP (live only with the external adapter)
    property bool monAvail: false
    property var monAp: ({})
    property int monClients: 0
    function refreshMon() {
        // for a synthetic ☠ attacker entry, the real monitor record lives under
        // the victim AP's BSSID, not the attacker's (possibly spoofed) MAC.
        var b = (ap && ap.victimBssid) ? ap.victimBssid : (ap ? ap.bssid : "")
        monAvail = sniffer.available
        monAp = (b && sniffer.available) ? sniffer.apForBssid(b) : ({})
        monClients = (b && sniffer.available) ? sniffer.clientCount(b) : 0
    }
    property bool _attached: false
    onStatusChanged: {
        if (status === PageStatus.Active) {
            refreshMon()
            // always reachable by swiping right; the client map shows a hint
            // when there's no monitor adapter / no clients yet.
            if (!_attached) {
                _attached = true
                pageStack.pushAttached(Qt.resolvedUrl("ClientTopologyPage.qml"), { ap: ap })
            }
        }
    }
    Connections { target: sniffer; onChanged: detailPage.refreshMon() }
    Component.onCompleted: refreshMon()

    function compassName(deg) {
        var names = ["N", "NE", "E", "SE", "S", "SW", "W", "NW"]
        return names[Math.round(((deg % 360) + 360) % 360 / 45) % 8]
    }

    function fmtDist(d) {
        if (d === undefined || d < 0)
            return qsTr("unknown")
        if (d < 1)
            return "< 1 m"
        if (d < 10)
            return d.toFixed(1) + " m"
        return Math.round(d) + " m"
    }

    function macInfo(m) {
        if (!m || m.length === 0) return "—"
        if (("" + m).toUpperCase().indexOf("FF:FF:FF") === 0)
            return qsTr("all clients (broadcast)")
        return m
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge

        VerticalScrollDecorator {}

        Column {
            id: col
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader {
                title: ap && ap.name && ap.name.length > 0 ? ap.name : qsTr("(hidden network)")
            }

            // --- Hotspot badge: wifi icon in a circle ---
            WifiIcon {
                anchors.horizontalCenter: parent.horizontalCenter
                width: Theme.itemSizeHuge
                height: width
                shape: "circle"
                fg: ap ? ap.secColor : Theme.highlightColor
                bg: Theme.rgba(ap ? ap.secColor : Theme.highlightColor, 0.18)
            }

            Label {
                anchors.horizontalCenter: parent.horizontalCenter
                text: (ap ? ap.secLabel : "") + (ap && ap.wps ? "  ·  WPS" : "")
                color: ap ? ap.secColor : Theme.primaryColor
                font.bold: true
            }

            Label {
                anchors.horizontalCenter: parent.horizontalCenter
                width: parent.width - 2 * Theme.horizontalPageMargin
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                visible: ap && (ap.secRisk === "critical" || ap.wps)
                text: {
                    if (!ap) return ""
                    if (ap.secRisk === "critical")
                        return qsTr("Insecure encryption — avoid sensitive use.")
                    if (ap.wps)
                        return qsTr("WPS is enabled — a known attack surface.")
                    return ""
                }
            }

            // --- Deauth attacker fingerprint (only for synthetic ☠ entries) ---
            SectionHeader { visible: ap && ap.attack === true; text: qsTr("☠ Deauth attacker") }
            Label {
                visible: ap && ap.attack === true
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: "#FF6D00"
                text: qsTr("This device is flooding deauth/disassoc frames — an active denial-of-service against the network below. Walk toward a stronger signal (smaller distance) to locate it.")
            }
            DetailItem {
                visible: ap && ap.attack === true
                label: qsTr("Attacker MAC (sender)")
                value: !ap ? "" : ((ap.attacker && ap.attacker.length ? ap.attacker : ap.bssid)
                       + (ap.attacker && ap.victimBssid
                          && ("" + ap.attacker).toUpperCase() === ("" + ap.victimBssid).toUpperCase()
                          ? "   ⚠ " + qsTr("spoofed AP MAC") : ""))
            }
            DetailItem {
                visible: ap && ap.attack === true
                label: qsTr("Attacked network")
                value: !ap ? "" : ((ap.victimSsid && ap.victimSsid.length ? ap.victimSsid : qsTr("(hidden)"))
                       + "  ·  " + (ap.victimBssid || ""))
            }
            DetailItem {
                visible: ap && ap.attack === true
                label: qsTr("Attacked client")
                value: ap ? macInfo(ap.attackTarget) : ""
            }
            DetailItem {
                visible: ap && ap.attack === true
                label: qsTr("Attack signal · distance")
                value: !ap ? "" : ((ap.attackSig ? ap.attackSig : ap.dbm) + " dBm  ·  ~ " + fmtDist(ap.distance))
            }
            DetailItem {
                visible: ap && ap.attack === true
                label: qsTr("Deauth rate · reason")
                value: ap ? ((ap.deauthRate || 0) + "/3s  ·  " + qsTr("reason") + " " + (ap.attackReason || 0)) : ""
            }

            SectionHeader { text: qsTr("Radio") }

            DetailItem { label: qsTr("SSID"); value: ap && ap.name && ap.name.length ? ap.name : qsTr("(hidden)") }
            DetailItem { label: qsTr("BSSID (MAC)"); value: ap ? ap.bssid : "" }
            DetailItem {
                label: qsTr("Vendor")
                value: ap && ap.vendor && ap.vendor.length ? ap.vendor
                       : (ap && ap.laa ? qsTr("locally administered / randomized") : qsTr("unknown"))
            }
            DetailItem { label: qsTr("Security"); value: ap ? ap.secLabel : "" }
            DetailItem {
                visible: ap && ap.cipher && ap.cipher.length > 0
                label: qsTr("Cipher")
                value: ap ? (ap.cipher + (ap.cipher.indexOf("TKIP") >= 0 ? "  ⚠ weak" : "")) : ""
            }
            DetailItem {
                visible: ap && ap.pmf && ap.pmf.length > 0
                label: qsTr("Mgmt frame protection")
                value: !ap ? "" : ap.pmf === "required" ? qsTr("required — deauth‑proof")
                       : ap.pmf === "optional" ? qsTr("optional")
                       : qsTr("off — deauth possible")
            }
            DetailItem { label: qsTr("Band"); value: ap ? ap.band : "" }
            DetailItem { label: qsTr("Channel"); value: ap ? "" + ap.channel : "" }
            DetailItem { label: qsTr("Channel width"); value: ap && ap.chWidth ? ap.chWidth + " MHz" : "" }
            DetailItem { label: qsTr("Standard"); value: ap && ap.phy ? "802.11" + ap.phy : "" }
            DetailItem { label: qsTr("Frequency"); value: ap ? ap.frequency + " MHz" : "" }
            DetailItem { label: qsTr("Signal"); value: ap ? (ap.dbm + " dBm  (" + ap.strength + " %)") : "" }
            DetailItem { label: qsTr("Distance (est.)"); value: ap ? "~ " + fmtDist(ap.distance) : "" }
            DetailItem {
                visible: ap && ap.bssStations >= 0
                label: qsTr("Advertised clients")
                value: ap ? (ap.bssStations + (ap.bssUtil >= 0
                             ? "  ·  " + ap.bssUtil + "% " + qsTr("ch. load") : "")) : ""
            }
            DetailItem {
                visible: ap && ap.country && ap.country.length > 0
                label: qsTr("Country / regulatory")
                value: ap ? ap.country : ""
            }
            DetailItem { label: qsTr("Hidden SSID"); value: ap && ap.hidden ? qsTr("yes") : qsTr("no") }
            DetailItem {
                label: qsTr("Randomized MAC")
                value: ap && ap.laa ? qsTr("yes — private address") : qsTr("no")
            }
            DetailItem {
                label: qsTr("Direction (from N)")
                value: myBearing >= 0
                       ? compassName(myBearing) + "  (" + Math.round(myBearing) + "°)"
                       : "—  " + qsTr("not set")
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Set direction (facing it now)")
                onClicked: if (ap) setBearing(ap.bssid, sensor.heading)
            }

            SectionHeader { text: qsTr("Device (from WPS broadcast)") }

            DetailItem { label: qsTr("Manufacturer"); value: ap && ap.manufacturer && ap.manufacturer.length ? ap.manufacturer : "—" }
            DetailItem { label: qsTr("Model"); value: ap && ap.model && ap.model.length ? ap.model : "—" }
            DetailItem { label: qsTr("Device name"); value: ap && ap.deviceName && ap.deviceName.length ? ap.deviceName : "—" }
            DetailItem { label: qsTr("Serial"); value: ap && ap.serial && ap.serial.length ? ap.serial : "—" }
            DetailItem {
                label: qsTr("WPS")
                value: ap && ap.wps ? qsTr("enabled — attack surface") : qsTr("not advertised")
            }

            SectionHeader { text: qsTr("Monitor mode (Tier 3)") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: monAvail ? Theme.highlightColor : Theme.secondaryColor
                text: monAvail
                      ? qsTr("Live 802.11 capture via the external adapter. Swipe left for the client map.")
                      : qsTr("Swipe left for the client map. Live client data needs an external monitor-mode adapter (e.g. Alfa RTL8812AU); without it the fields below are N/A.")
            }

            DetailItem {
                label: qsTr("Connected clients")
                value: !monAvail ? "—  " + qsTr("N/A")
                       : (monClients > 0 ? monClients + "  ·  " + qsTr("swipe ← for map")
                                         : qsTr("none seen yet"))
            }
            DetailItem {
                label: qsTr("Deauth / disassoc attack")
                value: !monAvail ? "—  " + qsTr("N/A")
                       : (monAp && monAp.attack
                          ? "☠ " + qsTr("YES") + "  (" + (monAp.deauthRate || 0) + "/3s, reason " + (monAp.reason || 0) + ")"
                          : qsTr("none") + "  (" + ((monAp && (monAp.deauths + monAp.disassocs)) || 0) + " " + qsTr("seen") + ")")
            }
            DetailItem {
                label: qsTr("Same-SSID APs (evil twin)")
                value: !monAvail ? "—  " + qsTr("N/A")
                       : (monAp && monAp.siblings > 0
                          ? "⚠ " + (monAp.siblings + 1) + " " + qsTr("share this SSID")
                          : qsTr("unique"))
            }
            DetailItem {
                label: qsTr("Monitor signal · beacons")
                value: !monAvail ? "—  " + qsTr("N/A")
                       : ((monAp && monAp.signal ? monAp.signal + " dBm" : "?")
                          + "  ·  " + ((monAp && monAp.beacons) || 0))
            }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: qsTr("Search CVEs for this model")
                onClicked: {
                    // NEVER the SSID (user-chosen, not a model). Use the vendor
                    // and, only if it looks like a real model, the WPS model.
                    var v = ("" + (ap && ap.manufacturer ? ap.manufacturer : ""))
                            .replace(/[()!]/g, " ").replace(/\s+/g, " ").trim()
                    var m = ("" + (ap && ap.model ? ap.model : "")).trim()
                    var t = v
                    if (m.length >= 3 && m.toUpperCase() !== "FBOX"
                            && m.toLowerCase() !== v.toLowerCase())
                        t = (v + " " + m).trim()
                    pageStack.push(Qt.resolvedUrl("CvePage.qml"), { terms: t })
                }
            }
        }
    }
}
