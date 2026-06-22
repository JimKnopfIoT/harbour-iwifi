/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Heading-oriented radar. "Up" = where the phone points (relative heading from the
  gyro+accelerometer SensorReader; set the reference in the direction finder).
  The phone is at the centre; every AP sits at its ESTIMATED DISTANCE on a LINEAR
  scale where the most-distant AP reaches the screen edge (long vertical axis).
  An AP off to the side of the narrow screen becomes an EDGE ARROW + label; turn
  toward it and it slides onto the long axis as a proper device. Turning rotates
  the map; devices keep their estimated world position.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

import "../views"

Page {
    id: radarPage

    property var apList: []
    property real dmax: 8
    property real zoom: 1.0
    property real dEff: Math.max(1, dmax / zoom)   // distance at the screen edge
    property real heading: sensor.heading + 180   // compass, shared by markers + OSM
    property string radarBand: "all"        // "all" | "2.4" | "5"
    property var pinned: ({})               // tapped hotspots: bssid -> cached data
    function pin(ap) { var p = pinned; p[ap.bssid] = ap; pinned = p }

    // filters — set by tapping the corner mini-charts
    property int chFilter: 0                // 0 = all channels
    property int rssiBin: 0                 // 0 = all; else bucket (-40..-90, 10 dBm)
    property var chList: []
    property var chCounts: ({})             // channel -> AP count
    property var rssiCounts: ({})           // bucket(dBm) -> AP count

    function rssiBucket(dbm) {
        var b = Math.floor(dbm / 10) * 10
        if (b > -40) b = -40
        if (b < -90) b = -90
        return b
    }

    function rebuild() {
        var arr = []
        var mx = 4
        var src = iwscan.aps
        var live = {}, p = pinned, refreshed = false
        var chset = {}, chc = {}, rsc = {}
        for (var i = 0; i < src.length; ++i) {
            var e = enrichScan(src[i])
            if (radarBand === "2.4" && e.frequency >= 2500) continue
            if (radarBand === "5" && e.frequency < 2500) continue
            chset[e.channel] = true
            chc[e.channel] = (chc[e.channel] || 0) + 1
            var rb = rssiBucket(e.dbm)
            rsc[rb] = (rsc[rb] || 0) + 1
            var isPinned = (p[e.bssid] !== undefined)
            if (isPinned) { p[e.bssid] = e; refreshed = true }
            // channel / RSSI filters (pinned hotspots are exempt — they stay)
            if (!isPinned && chFilter > 0 && e.channel !== chFilter) continue
            if (!isPinned && rssiBin !== 0 && rb !== rssiBin) continue
            live[e.bssid] = true
            var d = (e.distance > 0 && e.distance < 300) ? e.distance : -1
            if (d > mx) mx = d
            arr.push(e)
        }
        for (var b in p) {
            if (!live[b]) {
                arr.push(p[b])
                var dd = p[b].distance
                if (dd > 0 && dd < 300 && dd > mx) mx = dd
            }
        }
        if (refreshed) pinned = p
        // live deauth attackers as their own ☠ markers, placed by attack RSSI
        var atk = attackerEntries()
        for (var ai = 0; ai < atk.length; ++ai) {
            var ae = atk[ai]
            if (radarBand === "2.4" && ae.frequency >= 2500) continue
            if (radarBand === "5" && ae.frequency < 2500) continue
            var ad = (ae.distance > 0 && ae.distance < 300) ? ae.distance : -1
            if (ad > mx) mx = ad
            arr.push(ae)
        }
        var cl = []
        for (var c in chset) cl.push(parseInt(c))
        cl.sort(function (a, b) { return a - b })
        chList = cl; chCounts = chc; rssiCounts = rsc
        arr.sort(function (a, b) { return a.distance - b.distance })
        apList = arr
        dmax = Math.max(4, mx)
    }

    // --- OpenStreetMap silhouette background (opt-in; needs GPS; zoom out to see) ---
    // Always starts OFF (and is switched off when the app backgrounds/closes),
    // so the user just enables it once and the fetch fires immediately — no
    // toggle-off-then-on dance to make it work on a fresh launch.
    property bool osmShow: false
    function setOsm(on) {
        osmShow = on
        showToast(on ? qsTr("Map background on (needs GPS; zoom out)") : qsTr("Map background off"))
        if (on) maybeFetchOsm()
    }
    // turn the map off when the app is no longer in the foreground
    Connections {
        target: Qt.application
        onStateChanged: {
            if (Qt.application.state !== Qt.ApplicationActive && radarPage.osmShow)
                radarPage.osmShow = false
        }
    }
    // OSM data lives in the C++ `osm` helper (QNetworkAccessManager with mirror
    // fallback — QML XMLHttpRequest can't fall back past a dead IPv4 host).
    // These mirror it so the canvas/attribution bindings stay unchanged.
    property var osmWays: osm.ways
    property real osmLat: osm.lat
    property real osmLon: osm.lon
    // only show the map up to 1.2× zoom — beyond that the radar is zoomed in on
    // nearby devices and the map's metric scale no longer matches.
    property real osmMaxZoom: 1.2
    property bool osmVisible: osmShow && gpsValid && zoom <= osmMaxZoom

    // show the live lat/lon readout under the title (toggle in the pulley);
    // always starts OFF so a fresh launch never reveals your position until you
    // explicitly turn it on.
    property bool showCoords: false
    function setShowCoords(on) { showCoords = on }
    function maybeFetchOsm() {
        if (!gpsEnabled || !gpsValid || !osmShow || osm.busy) return
        // only refetch once we've moved > 80 m from the last fetched centre
        if (osmWays.length > 0) {
            var dN = (gpsLat - osmLat) * 111320
            var dE = (gpsLon - osmLon) * 111320 * Math.cos(gpsLat * Math.PI / 180)
            if (Math.sqrt(dN * dN + dE * dE) < 80) return
        }
        osm.fetch(gpsLat, gpsLon, 400)
    }
    Connections {
        target: rootApp
        onGpsValidChanged: radarPage.maybeFetchOsm()
        onGpsLatChanged: radarPage.maybeFetchOsm()
    }
    // surface the fetch result (loaded / no mirror reachable) to the user
    Connections {
        target: osm
        onChanged: {
            if (radarPage.osmShow && !osm.busy && osm.status.length > 0)
                showToast(osm.status)
        }
    }

    Component.onCompleted: { rebuild(); sensor.start() }
    // share the motion sensor with the direction finder; keep it running so
    // neither page freezes the other's heading.
    property bool _attachedList: false
    onStatusChanged: {
        if (status === PageStatus.Active) {
            sensor.start()
            // swipe forward to the network list (like the old entry page)
            if (pageStack.depth === 1 && !_attachedList) {
                _attachedList = true
                pageStack.pushAttached(Qt.resolvedUrl("ListPage.qml"))
            }
        }
    }
    Connections {
        target: iwscan
        onUpdated: radarPage.rebuild()
    }
    // a deauth attack can begin between scans — refresh so the ☠ marker appears
    Connections {
        target: sniffer
        onChanged: radarPage.rebuild()
    }

    function pseudoBearing(bssid) {
        var h = 0
        for (var i = 0; i < bssid.length; ++i)
            h = (h * 31 + bssid.charCodeAt(i)) & 0xffff
        return h % 360
    }
    function worldBearing(ap) {
        var b = apBearings[ap.bssid]
        return (b !== undefined) ? b : pseudoBearing(ap.bssid)
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: height

        PullDownMenu {
            MenuItem {
                text: qsTr("About")
                onClicked: pageStack.push(Qt.resolvedUrl("AboutPage.qml"))
            }
            MenuItem {
                text: qsTr("GPS: %1").arg(!gpsEnabled ? qsTr("off")
                            : (gpsValid ? qsTr("on (fix)") : qsTr("on (acquiring…)")))
                onClicked: setGps(!gpsEnabled)
            }
            MenuItem {
                visible: gpsEnabled
                text: qsTr("Map (OSM): %1").arg(osmShow ? qsTr("on") : qsTr("off"))
                onClicked: setOsm(!osmShow)
            }
            MenuItem {
                visible: gpsEnabled
                text: qsTr("Coordinates: %1").arg(showCoords ? qsTr("on") : qsTr("off"))
                onClicked: setShowCoords(!showCoords)
            }
            MenuItem {
                text: qsTr("Monitor mode: %1").arg(monitorEnabled ? qsTr("on") : qsTr("off"))
                onClicked: setMonitor(!monitorEnabled)
            }
            MenuItem {
                text: qsTr("LAN devices (ARP)")
                onClicked: pageStack.push(Qt.resolvedUrl("ClientsPage.qml"))
            }
            MenuItem {
                text: qsTr("Band: %1").arg(radarBand === "all" ? qsTr("both")
                            : radarBand === "2.4" ? "2.4 GHz" : "5 GHz")
                onClicked: {
                    radarBand = radarBand === "all" ? "2.4"
                                : radarBand === "2.4" ? "5" : "all"
                    rebuild()
                }
            }
            MenuItem {
                visible: chFilter !== 0 || rssiBin !== 0
                text: qsTr("Clear filters")
                onClicked: { chFilter = 0; rssiBin = 0; rebuild() }
            }
            MenuItem {
                text: qsTr("Channel analysis")
                onClicked: pageStack.push(Qt.resolvedUrl("ChannelPage.qml"))
            }
            MenuItem {
                text: qsTr("Networks (list)")
                onClicked: pageStack.push(Qt.resolvedUrl("ListPage.qml"))
            }
        }

    Column {
        id: hdr
        anchors { top: parent.top; left: parent.left; right: parent.right
                  topMargin: Theme.paddingLarge }
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: qsTr("Radar")
            font.pixelSize: Theme.fontSizeLarge
            color: Theme.highlightColor
        }
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            font.pixelSize: Theme.fontSizeTiny
            color: Theme.secondaryColor
            text: qsTr("%1 dev · %5 · edge %2 m · %3× · facing %4°")
                  .arg(apList.length).arg(dEff.toFixed(0)).arg(zoom.toFixed(1))
                  .arg(Math.round(((heading % 360) + 360) % 360))
                  .arg(radarBand === "all" ? qsTr("2.4+5") : radarBand === "2.4" ? "2.4G" : "5G")
        }
        Label {
            visible: gpsEnabled && showCoords
            anchors.horizontalCenter: parent.horizontalCenter
            font.pixelSize: Theme.fontSizeTiny
            color: gpsValid ? Theme.highlightColor : Theme.secondaryColor
            text: gpsValid
                  ? "⌖ " + gpsLat.toFixed(5) + ", " + gpsLon.toFixed(5)
                    + (gpsAcc > 0 ? "  ±" + Math.round(gpsAcc) + "m" : "")
                  : qsTr("GPS acquiring…")
        }
    }

    // top-left: APs per channel (tap a bar to filter)
    Item {
        z: 100
        anchors { top: hdr.bottom; left: parent.left
                  leftMargin: Theme.paddingMedium; topMargin: Theme.fontSizeTiny }
        width: parent.width * 0.44
        height: Theme.itemSizeMedium
        Label {
            anchors.bottom: chCanvas.top
            font.pixelSize: Theme.fontSizeTiny; color: Theme.secondaryColor
            text: qsTr("APs / channel")
        }
        Canvas {
            id: chCanvas
            anchors.fill: parent; anchors.topMargin: Theme.fontSizeTiny + 2
            onPaint: {
                var ctx = getContext("2d"); ctx.reset()
                var list = radarPage.chList, cc = radarPage.chCounts, n = list.length
                if (!n) return
                var maxc = 1, i
                for (i = 0; i < n; ++i) maxc = Math.max(maxc, cc[list[i]] || 0)
                var bw = width / n, pad = Math.min(bw * 0.18, 4)
                var lblH = Theme.fontSizeTiny + 3, cntH = Theme.fontSizeTiny + 2
                ctx.font = Theme.fontSizeTiny + "px sans-serif"; ctx.textAlign = "center"
                for (i = 0; i < n; ++i) {
                    var c = cc[list[i]] || 0, bh = (height - lblH - cntH) * c / maxc
                    var x = i * bw, sel = (list[i] === radarPage.chFilter)
                    ctx.fillStyle = sel ? Theme.highlightColor : Theme.rgba(Theme.primaryColor, 0.45)
                    ctx.fillRect(x + pad, height - lblH - bh, bw - 2 * pad, bh)
                    ctx.fillStyle = sel ? Theme.highlightColor : Theme.primaryColor
                    ctx.fillText(c, x + bw / 2, height - lblH - bh - 2)      // count on top
                    ctx.fillStyle = sel ? Theme.highlightColor : Theme.secondaryColor
                    ctx.fillText(list[i], x + bw / 2, height - 1)            // channel below
                }
            }
            Connections {
                target: radarPage
                onChCountsChanged: chCanvas.requestPaint()
                onChFilterChanged: chCanvas.requestPaint()
            }
            Component.onCompleted: requestPaint()
        }
        MouseArea {
            anchors.fill: parent
            onClicked: {
                var n = radarPage.chList.length; if (!n) return
                var idx = Math.floor(mouse.x / (width / n))
                if (idx < 0 || idx >= n) return
                var ch = radarPage.chList[idx]
                radarPage.chFilter = (radarPage.chFilter === ch) ? 0 : ch
                radarPage.rebuild()
            }
        }
    }

    // top-right: APs per RSSI bucket (10 dBm; tap a bar to filter)
    Item {
        id: rsBox
        z: 100
        anchors { top: hdr.bottom; right: parent.right
                  rightMargin: Theme.paddingMedium; topMargin: Theme.fontSizeTiny }
        width: parent.width * 0.44
        height: Theme.itemSizeMedium
        property var buckets: [-40, -50, -60, -70, -80, -90]
        Label {
            anchors { bottom: rsCanvas.top; right: parent.right }
            font.pixelSize: Theme.fontSizeTiny; color: Theme.secondaryColor
            text: qsTr("APs / RSSI")
        }
        Canvas {
            id: rsCanvas
            anchors.fill: parent; anchors.topMargin: Theme.fontSizeTiny + 2
            onPaint: {
                var ctx = getContext("2d"); ctx.reset()
                var bk = rsBox.buckets, rc = radarPage.rssiCounts, n = bk.length
                var maxc = 1, i
                for (i = 0; i < n; ++i) maxc = Math.max(maxc, rc[bk[i]] || 0)
                var bw = width / n, pad = Math.min(bw * 0.18, 4)
                var lblH = Theme.fontSizeTiny + 3, cntH = Theme.fontSizeTiny + 2
                ctx.font = Theme.fontSizeTiny + "px sans-serif"; ctx.textAlign = "center"
                for (i = 0; i < n; ++i) {
                    var c = rc[bk[i]] || 0, bh = (height - lblH - cntH) * c / maxc
                    var x = i * bw, sel = (bk[i] === radarPage.rssiBin)
                    ctx.fillStyle = sel ? Theme.highlightColor : Theme.rgba(Theme.primaryColor, 0.45)
                    ctx.fillRect(x + pad, height - lblH - bh, bw - 2 * pad, bh)
                    ctx.fillStyle = sel ? Theme.highlightColor : Theme.primaryColor
                    ctx.fillText(c, x + bw / 2, height - lblH - bh - 2)      // count on top
                    ctx.fillStyle = sel ? Theme.highlightColor : Theme.secondaryColor
                    ctx.fillText(bk[i], x + bw / 2, height - 1)              // bucket below
                }
            }
            Connections {
                target: radarPage
                onRssiCountsChanged: rsCanvas.requestPaint()
                onRssiBinChanged: rsCanvas.requestPaint()
            }
            Component.onCompleted: requestPaint()
        }
        MouseArea {
            anchors.fill: parent
            onClicked: {
                var bk = rsBox.buckets, n = bk.length
                var idx = Math.floor(mouse.x / (width / n))
                if (idx < 0 || idx >= n) return
                var v = bk[idx]
                radarPage.rssiBin = (radarPage.rssiBin === v) ? 0 : v
                radarPage.rebuild()
            }
        }
    }

    Item {
        id: radar
        anchors { top: hdr.bottom; left: parent.left; right: parent.right; bottom: zoomSlider.top }
        property real cx: width / 2
        property real cy: height / 2
        property real inset: Theme.itemSizeSmall * 0.6
        property real rscale: cy - inset

        // OSM silhouette background (drawn first = behind the rings/markers)
        Canvas {
            id: osmCanvas
            anchors.fill: parent
            visible: radarPage.osmVisible
            onPaint: {
                var ctx = getContext("2d"); ctx.reset()
                if (!radarPage.osmVisible) return
                var ways = radarPage.osmWays; if (!ways.length) return
                var ccx = radar.cx, ccy = radar.cy, rscale = radar.rscale
                var dEff = radarPage.dEff, h = radarPage.heading * Math.PI / 180
                var clat = radarPage.osmLat, clon = radarPage.osmLon
                var coslat = Math.cos(clat * Math.PI / 180)
                function proj(la, lo) {
                    var north = (la - clat) * 111320
                    var east = (lo - clon) * 111320 * coslat
                    // no offset: rotated another 90° (S→E), now aligned to raw bearing
                    var theta = Math.atan2(east, north) - h
                    var r = Math.sqrt(north * north + east * east) / dEff * rscale
                    return { x: ccx + Math.sin(theta) * r, y: ccy - Math.cos(theta) * r }
                }
                for (var i = 0; i < ways.length; ++i) {
                    var w = ways[i], pts = w.pts, j
                    ctx.beginPath()
                    for (j = 0; j < pts.length; ++j) {
                        var p = proj(pts[j].lat, pts[j].lon)
                        if (j === 0) ctx.moveTo(p.x, p.y); else ctx.lineTo(p.x, p.y)
                    }
                    if (w.building) {
                        ctx.closePath()
                        ctx.fillStyle = Theme.rgba(Theme.secondaryColor, 0.07)
                        ctx.fill()
                        ctx.strokeStyle = Theme.rgba(Theme.secondaryColor, 0.22); ctx.lineWidth = 1
                    } else {
                        ctx.strokeStyle = Theme.rgba(Theme.primaryColor, 0.28); ctx.lineWidth = 2
                    }
                    ctx.stroke()
                }
            }
            Connections {
                target: radarPage
                onOsmWaysChanged: osmCanvas.requestPaint()
                onOsmShowChanged: osmCanvas.requestPaint()
                onOsmVisibleChanged: osmCanvas.requestPaint()
            }
            Timer {
                interval: 160
                running: radarPage.osmVisible
                repeat: true
                onTriggered: osmCanvas.requestPaint()
            }
        }

        Label {
            z: 60
            visible: radarPage.osmVisible && radarPage.osmWays.length > 0
            anchors { left: parent.left; bottom: parent.bottom; margins: Theme.paddingSmall }
            font.pixelSize: Theme.fontSizeTiny
            color: Theme.rgba(Theme.secondaryColor, 0.7)
            text: "© OpenStreetMap"
        }

        Canvas {
            id: ringCanvas
            anchors.fill: parent
            property real d: radarPage.dEff
            onDChanged: requestPaint()
            onWidthChanged: requestPaint()
            onHeightChanged: requestPaint()
            onPaint: {
                var ctx = getContext("2d"); ctx.reset()
                var cx = radar.cx, cy = radar.cy
                ctx.strokeStyle = Theme.rgba(Theme.primaryColor, 0.28)
                ctx.fillStyle = Theme.secondaryColor
                ctx.font = Theme.fontSizeExtraSmall + "px sans-serif"; ctx.textAlign = "center"
                var fr = [0.25, 0.5, 0.75, 1.0]
                for (var i = 0; i < fr.length; ++i) {
                    var r = radar.rscale * fr[i]
                    ctx.lineWidth = (fr[i] === 1.0) ? 2 : 1
                    ctx.beginPath(); ctx.arc(cx, cy, r, 0, 2 * Math.PI); ctx.stroke()
                    ctx.fillText((radarPage.dEff * fr[i]).toFixed(0) + " m", cx, cy - r - 8)
                }
            }
        }

        // "you face this way" — always up in heading-up mode
        Rectangle {
            width: Theme.paddingSmall / 2
            height: radar.rscale
            radius: width / 2
            color: Theme.rgba(Theme.highlightColor, 0.55)
            antialiasing: true
            x: radar.cx - width / 2
            y: radar.cy - height
        }
        Label {
            text: qsTr("you ▲")
            font.pixelSize: Theme.fontSizeTiny
            color: Theme.highlightColor
            x: radar.cx - width / 2
            y: radar.cy - radar.rscale - height
        }

        Rectangle {
            width: Theme.paddingMedium; height: width; radius: width / 2
            color: Theme.highlightColor
            x: radar.cx - width / 2; y: radar.cy - height / 2
        }

        Repeater {
            model: apList
            delegate: Item {
                id: mk
                // HEADING-UP: where you point is always up; devices rotate
                // opposite to your turn so they keep their real-world direction.
                // +180 flips the device cloud to match the phone's orientation.
                property real theta: (radarPage.worldBearing(modelData) + radarPage.heading) * Math.PI / 180   // heading sign matches the N/S mirror so markers stay world-stabilized while turning
                property real ux: -Math.sin(theta)   // mirrored across the N/S axis (E↔W)
                property real uy: -Math.cos(theta)
                property real dnorm: (modelData.distance > 0 && modelData.distance < 300)
                                     ? modelData.distance / radarPage.dEff : 1
                property real rPix: radar.rscale * dnorm
                property bool measured: apBearings[modelData.bssid] !== undefined
                property bool pinned: radarPage.pinned[modelData.bssid] !== undefined
                property bool solid: measured || pinned
                property real halfW: radar.cx - radar.inset
                property real halfH: radar.cy - radar.inset
                property real tEdge: Math.min(
                        (Math.abs(ux) < 1e-4) ? 1e9 : halfW / Math.abs(ux),
                        (Math.abs(uy) < 1e-4) ? 1e9 : halfH / Math.abs(uy))
                property bool onScreen: rPix <= tEdge
                property real px: radar.cx + ux * (onScreen ? rPix : tEdge)
                property real py: radar.cy + uy * (onScreen ? rPix : tEdge)

                width: Theme.iconSizeSmall; height: width
                x: px - width / 2
                y: py - height / 2

                // solid fill = bearing measured (real direction);
                // hollow outline = provisional (angle is a placeholder).
                Rectangle {
                    visible: mk.onScreen && modelData.attack !== true
                    anchors.fill: parent
                    radius: width / 2
                    color: mk.solid ? modelData.secColor : "transparent"
                    opacity: 0.95
                    border.color: mk.solid ? "white" : modelData.secColor
                    border.width: mk.solid ? 3 : 2
                }
                // deauth attacker: orange skull, placed by its attack RSSI
                Label {
                    visible: mk.onScreen && modelData.attack === true
                    anchors.centerIn: parent
                    text: "☠"
                    color: "#FF6D00"
                    font.pixelSize: Theme.iconSizeSmall
                }
                Label {
                    visible: !mk.onScreen
                    anchors.centerIn: parent
                    text: modelData.attack === true ? "☠" : "➤"
                    color: modelData.attack === true ? "#FF6D00" : modelData.secColor
                    font.pixelSize: Theme.fontSizeLarge
                    rotation: modelData.attack === true ? 0
                              : Math.atan2(mk.uy, mk.ux) * 180 / Math.PI
                }
                Label {
                    id: nameLbl
                    anchors { horizontalCenter: parent.horizontalCenter; top: parent.bottom }
                    width: Theme.itemSizeMedium
                    horizontalAlignment: Text.AlignHCenter
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeTiny
                    color: Theme.primaryColor
                    text: (modelData.name && modelData.name.length ? modelData.name
                                                                   : (modelData.vendor || "?"))
                          + (mk.onScreen ? "" : "  " + Math.round(modelData.distance) + "m")
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: {
                        radarPage.pin(modelData)          // cache + fill the marker
                        pageStack.push(Qt.resolvedUrl("DetailPage.qml"), { ap: modelData })
                    }
                }
            }
        }

        // Two-finger pinch to zoom. Drives the slider (not zoom directly) so the
        // on-screen zoom factor stays visible in both the slider and the header.
        PinchArea {
            anchors.fill: parent
            property real startZoom: 1.0
            onPinchStarted: startZoom = radarPage.zoom
            onPinchUpdated: {
                var z = startZoom * pinch.scale
                z = Math.max(zoomSlider.minimumValue,
                             Math.min(zoomSlider.maximumValue, z))
                zoomSlider.value = z
            }
        }
    }

    Slider {
        id: zoomSlider
        anchors { bottom: legend.top; left: parent.left; right: parent.right }
        minimumValue: 0.1
        maximumValue: 8.0
        value: 1.0
        stepSize: 0.1
        label: qsTr("Zoom — out for the map, in for the devices")
        valueText: value.toFixed(1) + "×"
        onValueChanged: radarPage.zoom = value
    }

    Label {
        id: legend
        anchors { bottom: parent.bottom; left: parent.left; right: parent.right; margins: Theme.paddingMedium }
        wrapMode: Text.WordWrap
        font.pixelSize: Theme.fontSizeExtraSmall
        color: Theme.secondaryColor
        text: qsTr("Up = where you point (compass). Radius = estimated distance — farthest AP at the edge; zoom to spread out near devices. Side arrows = APs off the narrow screen. Note: each device's ANGLE is only a placeholder — without a compass bearing per AP, only the distance is reliable.")
    }
    }
}
