/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Based on WiFi Analyzer by Petr Vytovtov (osanwe), GPLv3.
  Extensions Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

import "../views"

Page {
    id: listPage

    // Enriched + sorted snapshot of the live ConnMan model.
    property var apList: []

    // re-sort only every Nth scan (so entries don't jump every 2.5 s)
    property int sinceSort: 0
    readonly property int sortEvery: 5

    // pick a readable text colour for a coloured badge (dark on light bg)
    function textOn(hex) {
        var c = ("" + hex).replace("#", "")
        if (c.length < 6) return "white"
        var r = parseInt(c.substr(0, 2), 16)
        var g = parseInt(c.substr(2, 2), 16)
        var b = parseInt(c.substr(4, 2), 16)
        return (0.299 * r + 0.587 * g + 0.114 * b) > 140 ? "#1c1c1c" : "white"
    }

    function fmtDist(d) {
        if (d === undefined || d < 0)
            return "?"
        if (d < 1)
            return "<1 m"
        if (d < 10)
            return d.toFixed(1) + " m"
        return Math.round(d) + " m"
    }

    function rebuild() {
        var arr = []
        var src = iwscan.aps
        for (var i = 0; i < src.length; ++i) {
            arr.push(enrichScan(src[i]))
        }
        // surface live deauth attackers as their own orange ☠ entries
        var atk = attackerEntries()
        for (var k = 0; k < atk.length; ++k) arr.push(atk[k])
        // strongest signal on top, weakest at the bottom
        arr.sort(function (a, b) {
            return b.strength - a.strength
        })
        apList = arr
    }

    // Re-sort at most every `sortEvery` scans, and never while the user is
    // touching/scrolling the list or parked below the top — otherwise entries
    // jump away and you can't tap the one at the bottom.
    function maybeRebuild() {
        if (apList.length === 0) {        // first populate: show immediately
            sinceSort = 0
            rebuild()
            return
        }
        if (sinceSort < sortEvery)
            return
        if (!wifiInfoList.atYBeginning || wifiInfoList.moving || wifiInfoList.dragging)
            return                        // user is busy with the list; wait
        sinceSort = 0
        rebuild()
    }

    Component.onCompleted: rebuild()

    Connections {
        target: iwscan
        onUpdated: {
            listPage.sinceSort++
            listPage.maybeRebuild()
        }
    }

    // a deauth attack can start between scans — refresh promptly so the orange
    // ☠ attacker entry appears as soon as the sniffer reports it.
    Connections {
        target: sniffer
        onChanged: { listPage.sinceSort = listPage.sortEvery; listPage.maybeRebuild() }
    }

    ViewPlaceholder {
        enabled: !networksList.powered
        text: qsTr("Please, turn WiFi on")
    }

    ViewPlaceholder {
        enabled: networksList.powered && apList.length === 0
        text: qsTr("There are no WiFi networks")
    }

    SilicaListView {
        id: wifiInfoList
        anchors.fill: parent

        // catch up on a deferred re-sort once the user stops / returns to top
        onMovementEnded: listPage.maybeRebuild()
        onAtYBeginningChanged: if (atYBeginning) listPage.maybeRebuild()

        TopMenu {
            pageName: "ListPage.qml"
        }

        header: PageHeader {
            title: qsTr("Networks") + " (" + apList.length + ")"
        }

        model: apList

        delegate: BackgroundItem {
            id: del
            width: wifiInfoList.width
            // tight 3 lines + a clear gap to the next hotspot
            height: content.height + Theme.paddingLarge

            onClicked: pageStack.push(Qt.resolvedUrl("DetailPage.qml"),
                                      { ap: modelData })

            Column {
                id: content
                anchors {
                    left: parent.left
                    right: parent.right
                    leftMargin: Theme.horizontalPageMargin
                    rightMargin: Theme.horizontalPageMargin
                    top: parent.top
                    topMargin: Theme.paddingSmall
                }
                spacing: Theme.paddingSmall / 2

                Row {
                    width: parent.width
                    Label {
                        width: parent.width * 0.62
                        text: modelData.name && modelData.name.length > 0
                              ? modelData.name : qsTr("(hidden)")
                        font.bold: true
                        color: del.highlighted ? Theme.highlightColor : Theme.primaryColor
                        truncationMode: TruncationMode.Fade
                    }
                    Label {
                        width: parent.width * 0.38
                        horizontalAlignment: Text.AlignRight
                        text: modelData.dbm + " dBm"
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.secondaryColor
                    }
                }

                Row {
                    width: parent.width
                    spacing: Theme.paddingMedium
                    Label {
                        width: parent.width * 0.62
                        text: (modelData.vendor && modelData.vendor.length > 0
                               ? modelData.vendor
                               : (modelData.laa ? qsTr("randomized MAC") : modelData.bssid))
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        truncationMode: TruncationMode.Fade
                    }
                    Label {
                        width: parent.width * 0.38 - Theme.paddingMedium
                        horizontalAlignment: Text.AlignRight
                        text: modelData.band + " · " + qsTr("Ch") + " " + modelData.channel
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                    }
                }

                Row {
                    width: parent.width
                    spacing: Theme.paddingMedium
                    Rectangle {
                        id: badge
                        radius: Theme.paddingSmall / 2
                        color: modelData.secColor
                        height: secLbl.height + Theme.paddingSmall / 2
                        width: secLbl.width + Theme.paddingMedium
                        anchors.verticalCenter: parent.verticalCenter
                        Label {
                            id: secLbl
                            anchors.centerIn: parent
                            text: modelData.secLabel + (modelData.wps ? " · WPS" : "")
                            font.pixelSize: Theme.fontSizeTiny
                            color: textOn(modelData.secColor)
                        }
                    }
                    Label {
                        text: "~ " + fmtDist(modelData.distance)
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    ProgressBar {
                        width: parent.width * 0.22
                        anchors.verticalCenter: parent.verticalCenter
                        minimumValue: 0
                        maximumValue: 100
                        value: modelData.strength
                    }
                    // one white dot per associated Wi-Fi client (monitor mode)
                    Row {
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Theme.paddingSmall / 2
                        // per-AP associated-client count (reacts to each snapshot)
                        property int n: (sniffer.aps, sniffer.clientCount(modelData.bssid))
                        Repeater {
                            model: Math.min(parent.n, 8)
                            Rectangle {
                                width: Theme.paddingSmall; height: width; radius: width / 2
                                color: Theme.primaryColor
                                anchors.verticalCenter: parent.verticalCenter
                            }
                        }
                        Label {
                            visible: parent.n > 8
                            text: "+"
                            font.pixelSize: Theme.fontSizeTiny
                            color: Theme.primaryColor
                            anchors.verticalCenter: parent.verticalCenter
                        }
                    }
                }
            }
        }

        VerticalScrollDecorator {}
    }
}
