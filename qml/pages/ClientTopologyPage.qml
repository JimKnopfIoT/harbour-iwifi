/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Tier-3 (external monitor adapter) only: a mesh diagram of one network. The AP
  with the most beacons (the router) sits in the centre; other APs sharing the
  same SSID (repeaters) are drawn as their own nodes with a thick back-haul line.

  PRIVACY: connected clients are shown ONLY as anonymous dots reflecting the
  count — no MAC, vendor, OS, traffic, probed networks or any per-device data.
  Tap a router/repeater node for its (AP-level) details. Reached by swiping from
  the detail page; shows a hint when no monitor adapter is present.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

Page {
    id: topo

    property var ap
    property var hitboxes: []      // [{x,y,r,info}] for AP/repeater nodes only
    property var selected: null    // info map of the tapped AP node
    property real zoom: 1.0
    property real panX: 0
    property real panY: 0

    Connections {
        target: sniffer
        onChanged: canvas.requestPaint()
    }

    // Without the external monitor adapter there is no live data; show a hint
    // instead of an empty canvas (the page is always reachable by swiping).
    ViewPlaceholder {
        enabled: !sniffer.available
        text: qsTr("No client map")
        hintText: qsTr("Connect an external monitor-mode adapter (e.g. Alfa RTL8812AU) to see how many clients are connected to this network.")
    }

    // Same-SSID APs (router + repeaters), each with its associated-client COUNT.
    function meshNodes() {
        if (!ap) return []
        var ssid = ("" + (ap.name || ""))
        var all = sniffer.aps, mesh = [], i
        for (i = 0; i < all.length; ++i) {
            var a = all[i]
            if (a.bssid === ap.bssid || (ssid.length && a.ssid === ssid)) {
                var m = {}
                for (var k in a) m[k] = a[k]
                m.clientCount = sniffer.clientCount(a.bssid)
                mesh.push(m)
            }
        }
        mesh.sort(function (x, y) { return (y.beacons || 0) - (x.beacons || 0) })
        return mesh
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height

        Column {
            id: column
            width: parent.width
            spacing: Theme.paddingSmall

            PageHeader {
                title: ap && ap.name && ap.name.length ? ap.name : qsTr("Network")
                // in a mesh the shared name spans all APs → it's the ESSID
                description: qsTr("ESSID")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: {
                    var m = meshNodes(), nc = 0
                    for (var i = 0; i < m.length; ++i) nc += (m[i].clientCount || 0)
                    return qsTr("%1 AP(s) · %2 client(s)").arg(m.length).arg(nc)
                           + (m.length > 1 ? "  ·  " + qsTr("router + repeaters · tap a node")
                                           : "  ·  " + qsTr("tap a node"))
                }
            }

            Item {
                width: topo.width
                height: Math.max(topo.height - column.y - Theme.itemSizeMedium, topo.width * 1.1)

                Canvas {
                    id: canvas
                    anchors.fill: parent

                    onPaint: {
                        var ctx = getContext("2d")
                        ctx.reset()
                        var z = topo.zoom
                        var cx = width / 2 + topo.panX, cy = height / 2 + topo.panY
                        var base = (Math.min(width, height) / 2) * z
                        var hb = []

                        var fLabel = Theme.fontSizeExtraSmall * Math.max(0.8, Math.min(1.7, z))
                        var apR = (Theme.itemSizeMedium / 2) * z
                        var repR = (Theme.itemSizeSmall / 2) * z
                        var dotR = Theme.paddingSmall * 0.9 * z
                        var R1 = base * 0.52
                        var subR = base * 0.22

                        var mesh = meshNodes()
                        if (mesh.length === 0) { topo.hitboxes = hb; return }
                        var main = mesh[0], repeaters = mesh.slice(1)

                        function apInfo(a) {
                            return { ssid: a.ssid, bssid: a.bssid, channel: a.channel,
                                     signal: a.signal, beacons: a.beacons,
                                     clients: (a.clientCount || 0),
                                     attack: a.attack, deauths: a.deauths, disassocs: a.disassocs,
                                     reason: a.reason, siblings: a.siblings }
                        }

                        // draw `count` anonymous client dots around (nodeX,nodeY)
                        // on a ring of radius `ringR`. Caps the dot count visually
                        // and prints the number when there are many.
                        function clientDots(nodeX, nodeY, ringR, count) {
                            if (count <= 0) return
                            var shown = Math.min(count, 24)
                            for (var d = 0; d < shown; ++d) {
                                var a = (d / shown) * 2 * Math.PI - Math.PI / 2
                                var x = nodeX + Math.cos(a) * ringR
                                var y = nodeY + Math.sin(a) * ringR
                                ctx.strokeStyle = Theme.rgba(Theme.highlightColor, 0.5)
                                ctx.lineWidth = 2
                                ctx.beginPath(); ctx.moveTo(nodeX, nodeY); ctx.lineTo(x, y); ctx.stroke()
                                ctx.fillStyle = Theme.highlightColor
                                ctx.beginPath(); ctx.arc(x, y, dotR, 0, 2 * Math.PI); ctx.fill()
                            }
                        }

                        // repeaters and the router's own clients laid out around the centre
                        var slots = []
                        var rc = main.clientCount || 0
                        var ringClients = Math.min(rc, 24)
                        for (var c = 0; c < ringClients; ++c) slots.push({ rep: false })
                        for (var r = 0; r < repeaters.length; ++r) slots.push({ rep: true, node: repeaters[r] })
                        var n = Math.max(1, slots.length)

                        for (var j = 0; j < slots.length; ++j) {
                            var ang = (j / n) * 2 * Math.PI - Math.PI / 2
                            var x = cx + Math.cos(ang) * R1
                            var y = cy + Math.sin(ang) * R1
                            if (!slots[j].rep) {
                                // a router client: just a dot + spoke
                                ctx.strokeStyle = Theme.rgba(Theme.highlightColor, 0.5)
                                ctx.lineWidth = 2
                                ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(x, y); ctx.stroke()
                                ctx.fillStyle = Theme.highlightColor
                                ctx.beginPath(); ctx.arc(x, y, dotR, 0, 2 * Math.PI); ctx.fill()
                            } else {
                                var rep = slots[j].node
                                ctx.strokeStyle = Theme.rgba(Theme.highlightColor, 0.85)
                                ctx.lineWidth = 7
                                ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(x, y); ctx.stroke()
                                clientDots(x, y, subR, rep.clientCount || 0)
                                ctx.fillStyle = rep.attack ? "#FF6D00" : (ap ? ap.secColor : Theme.highlightColor)
                                ctx.beginPath(); ctx.arc(x, y, repR, 0, 2 * Math.PI); ctx.fill()
                                hb.push({ x: x, y: y, r: repR, info: apInfo(rep) })
                                ctx.fillStyle = "white"; ctx.textAlign = "center"
                                ctx.font = (repR * 1.1) + "px sans-serif"
                                ctx.fillText(rep.attack ? "☠" : "⇆", x, y + repR * 0.4)
                                ctx.fillStyle = Theme.secondaryColor
                                ctx.font = fLabel + "px sans-serif"
                                ctx.fillText(rep.bssid, x, y + repR + fLabel + 4)
                            }
                        }

                        // if more router clients than we drew as dots, note the total
                        if (rc > ringClients) {
                            ctx.fillStyle = Theme.secondaryColor; ctx.textAlign = "center"
                            ctx.font = fLabel + "px sans-serif"
                            ctx.fillText("+" + (rc - ringClients), cx, cy + apR + 2 * fLabel + Theme.paddingSmall)
                        }

                        // central router node
                        ctx.fillStyle = main.attack ? "#FF6D00" : (ap ? ap.secColor : Theme.highlightColor)
                        ctx.beginPath(); ctx.arc(cx, cy, apR, 0, 2 * Math.PI); ctx.fill()
                        hb.push({ x: cx, y: cy, r: apR, info: apInfo(main) })
                        ctx.fillStyle = "white"; ctx.textAlign = "center"
                        ctx.font = (apR * 1.1) + "px sans-serif"
                        ctx.fillText(main.attack ? "☠" : "⌂", cx, cy + apR * 0.4)
                        // router ESSID: high-contrast (light + dark halo), with a
                        // small "ESSID" tag above it (the name spans the whole mesh)
                        ctx.save()
                        ctx.shadowColor = "black"; ctx.shadowBlur = 6
                        ctx.fillStyle = Theme.rgba(Theme.secondaryColor, 0.95)
                        ctx.font = fLabel + "px sans-serif"
                        ctx.fillText("ESSID", cx, cy - apR - Theme.paddingMedium - Theme.fontSizeMedium)
                        ctx.fillStyle = Theme.primaryColor
                        ctx.font = "bold " + Theme.fontSizeMedium + "px sans-serif"
                        ctx.fillText(main.ssid || (ap ? ap.name : ""), cx, cy - apR - Theme.paddingMedium)
                        ctx.restore()
                        ctx.fillStyle = Theme.secondaryColor
                        ctx.font = fLabel + "px sans-serif"
                        ctx.fillText(main.bssid, cx, cy + apR + fLabel + Theme.paddingSmall)

                        topo.hitboxes = hb
                    }
                    Component.onCompleted: requestPaint()
                }

                PinchArea {
                    anchors.fill: parent
                    property real z0: 1
                    onPinchStarted: z0 = topo.zoom
                    onPinchUpdated: {
                        topo.zoom = Math.max(0.5, Math.min(4, z0 * pinch.scale))
                        canvas.requestPaint()
                    }
                    MouseArea {
                        anchors.fill: parent
                        property real px: 0
                        property real py: 0
                        property bool moved: false
                        onPressed: { px = mouse.x; py = mouse.y; moved = false }
                        onPositionChanged: {
                            var dx = mouse.x - px, dy = mouse.y - py
                            if (Math.abs(dx) + Math.abs(dy) > 8) moved = true
                            topo.panX += dx; topo.panY += dy
                            px = mouse.x; py = mouse.y
                            canvas.requestPaint()
                        }
                        onClicked: {
                            if (moved) return
                            var best = null, bd = 1e9, i
                            for (i = 0; i < topo.hitboxes.length; ++i) {
                                var h = topo.hitboxes[i]
                                var d = Math.pow(mouse.x - h.x, 2) + Math.pow(mouse.y - h.y, 2)
                                if (d <= h.r * h.r && d < bd) { bd = d; best = h.info }
                            }
                            topo.selected = best
                        }
                        onDoubleClicked: {
                            topo.zoom = 1; topo.panX = 0; topo.panY = 0
                            canvas.requestPaint()
                        }
                    }
                }
            }
        }
        VerticalScrollDecorator {}
    }

    // tapped-node info panel — AP-level only (tap to dismiss)
    Rectangle {
        id: panel
        visible: topo.selected !== null
        anchors { left: parent.left; right: parent.right; bottom: parent.bottom }
        height: Math.min(topo.height * 0.6, infoCol.height + 2 * Theme.paddingLarge)
        color: Theme.rgba(Theme.highlightDimmerColor, 0.97)

        MouseArea { anchors.fill: parent; onClicked: topo.selected = null }

        SilicaFlickable {
            anchors.fill: parent
            anchors.margins: Theme.paddingLarge
            contentHeight: infoCol.height
            clip: true

            Column {
                id: infoCol
                width: parent.width
                spacing: Theme.paddingSmall / 2
                property var s: topo.selected ? topo.selected : ({})

                Label {
                    width: parent.width
                    font.pixelSize: Theme.fontSizeTiny; color: Theme.secondaryColor
                    text: qsTr("ESSID")
                }
                Label {
                    width: parent.width; wrapMode: Text.WordWrap
                    font.pixelSize: Theme.fontSizeMedium; color: Theme.highlightColor
                    text: infoCol.s.ssid && infoCol.s.ssid.length ? infoCol.s.ssid : qsTr("(hidden AP)")
                }
                Label {
                    width: parent.width; wrapMode: Text.WrapAnywhere
                    font.pixelSize: Theme.fontSizeSmall; color: Theme.primaryColor
                    text: "BSSID " + infoCol.s.bssid + "  ·  ch " + infoCol.s.channel
                          + "  ·  " + (infoCol.s.signal || "?") + " dBm  ·  "
                          + (infoCol.s.clients || 0) + " " + qsTr("clients")
                }
                Label {
                    width: parent.width; wrapMode: Text.WordWrap
                    font.pixelSize: Theme.fontSizeExtraSmall; color: Theme.secondaryColor
                    text: infoCol.s.attack
                          ? "☠ " + qsTr("deauth attack") + " (reason " + infoCol.s.reason + ")"
                          : qsTr("beacons") + " " + infoCol.s.beacons
                            + (infoCol.s.siblings > 0 ? "  ·  ⚠ " + (infoCol.s.siblings + 1) + " same‑SSID APs" : "")
                }
            }
        }
    }
}
