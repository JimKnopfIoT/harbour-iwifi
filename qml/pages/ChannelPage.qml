/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Based on WiFi Analyzer by Petr Vytovtov (osanwe), GPLv3.
  Extensions Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Channel / interference analysis (passive, internal chip — no monitor adapter).
  Buckets the live scan by channel and band, weights neighbours by signal and
  spectral overlap, and recommends the least-congested channel:
    - 2.4 GHz: scores the non-overlapping anchors 1 / 6 / 11 (20 MHz overlaps ±4).
    - 5 GHz : 20 MHz channels are non-overlapping → least-used wins; prefers the
      non-DFS channels (36–48, 149–165) so the AP never has to vacate on radar.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

Page {
    id: chPage

    property var rows24: []     // [{ch, count, load}]
    property var rows5: []
    property int best24: 0
    property int best5: 0
    property real maxLoad: 1

    function sigWeight(dbm) { return Math.max(0.05, (dbm + 100) / 60) }  // ~0..1.5

    function rebuild() {
        var src = iwscan.aps, i
        var c24 = {}, c5 = {}, n24 = {}, n5 = {}
        for (i = 0; i < src.length; ++i) {
            var e = enrichScan(src[i])
            var ch = e.channel, w = sigWeight(e.dbm)
            if (e.frequency < 2500) { c24[ch] = (c24[ch] || 0) + w; n24[ch] = (n24[ch] || 0) + 1 }
            else                    { c5[ch]  = (c5[ch]  || 0) + w; n5[ch]  = (n5[ch]  || 0) + 1 }
        }
        // 2.4 GHz: rows (only occupied channels) + recommend among 1/6/11
        var r24 = [], mx = 1, ch
        for (ch = 1; ch <= 13; ++ch)
            if (n24[ch]) { r24.push({ ch: ch, count: n24[ch], load: c24[ch] }); if (c24[ch] > mx) mx = c24[ch] }
        var anchors = [1, 6, 11], bestA = 1, bestScore = 1e9
        for (i = 0; i < anchors.length; ++i) {
            var a = anchors[i], score = 0
            for (ch = 1; ch <= 13; ++ch) {
                if (!c24[ch]) continue
                var d = Math.abs(a - ch)
                if (d <= 4) score += c24[ch] * (1 - d / 5)   // spectral overlap falloff
            }
            if (score < bestScore) { bestScore = score; bestA = a }
        }
        // 5 GHz: rows (only occupied channels) + recommend least-used non-DFS
        var r5 = [], pref = [36, 40, 44, 48, 149, 153, 157, 161, 165], bestF = 0, bestC = 1e9
        for (ch in c5) { r5.push({ ch: parseInt(ch), count: n5[ch], load: c5[ch] }); if (c5[ch] > mx) mx = c5[ch] }
        r5.sort(function (x, y) { return x.ch - y.ch })
        for (i = 0; i < pref.length; ++i) {
            var pc = pref[i], cc = c5[pc] || 0
            if (cc < bestC) { bestC = cc; bestF = pc }
        }
        rows24 = r24; rows5 = r5; best24 = bestA; best5 = bestF; maxLoad = mx
    }

    Component.onCompleted: rebuild()
    Connections { target: iwscan; onUpdated: chPage.rebuild() }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: col.height + Theme.paddingLarge
        VerticalScrollDecorator {}

        Column {
            id: col
            width: parent.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("Channel analysis") }

            // ---- 2.4 GHz ----
            SectionHeader { text: qsTr("2.4 GHz") }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: Theme.highlightColor
                text: rows24.length ? qsTr("Recommended channel: %1").arg(best24)
                                    : qsTr("No 2.4 GHz networks seen.")
            }
            Label {
                visible: rows24.length > 0
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("Only 1, 6 and 11 don't overlap; bars are signal-weighted "
                         + "load. No radar here — slower than 5 GHz but better range "
                         + "and wall penetration.")
            }
            Repeater {
                model: rows24
                delegate: chRow
            }

            // ---- 5 GHz ----
            SectionHeader { text: qsTr("5 GHz") }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                color: Theme.highlightColor
                text: best5 ? qsTr("Recommended channel: %1 (non-DFS)").arg(best5)
                            : qsTr("No 5 GHz networks seen.")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("DFS channels 52–144 share the band with weather, aviation "
                         + "and military radar: the AP must vacate on a radar hit and "
                         + "the link drops briefly. Non-DFS 36–48 and 149–165 never have "
                         + "to — most stable, so they are recommended. Wider channels "
                         + "(40/80/160 MHz) are faster but overlap more.")
            }
            Repeater {
                model: rows5
                delegate: chRow
            }
        }
    }

    // one channel row: number + bar + count
    Component {
        id: chRow
        Item {
            width: col.width
            height: Theme.itemSizeExtraSmall
            Label {
                id: chNum
                anchors.verticalCenter: parent.verticalCenter
                x: Theme.horizontalPageMargin
                width: Theme.itemSizeSmall
                text: qsTr("Ch") + " " + modelData.ch
                font.pixelSize: Theme.fontSizeSmall
            }
            Rectangle {
                id: bar
                anchors.verticalCenter: parent.verticalCenter
                x: chNum.x + chNum.width + Theme.paddingMedium
                height: Theme.paddingMedium
                radius: height / 2
                width: Math.max(Theme.paddingSmall,
                        (parent.width - x - Theme.itemSizeSmall - 2 * Theme.horizontalPageMargin)
                        * Math.min(1, modelData.load / chPage.maxLoad))
                color: Theme.highlightColor
                opacity: 0.7
            }
            Label {
                anchors { verticalCenter: parent.verticalCenter; right: parent.right; rightMargin: Theme.horizontalPageMargin }
                text: modelData.count + " AP"
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
            }
        }
    }
}
