/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  CVE list for a router model (NIST NVD). The search term is prefilled from the
  WPS manufacturer + SSID and can be edited (passive scans rarely give the exact
  model, so let the user refine it).
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

Page {
    id: cvePage

    property string terms: ""

    function sevColor(s) {
        var u = ("" + s).toUpperCase()
        if (u === "CRITICAL") return "#D32F2F"
        if (u === "HIGH") return "#F44336"
        if (u === "MEDIUM") return "#FF9800"
        if (u === "LOW") return "#8BC34A"
        return Theme.secondaryColor
    }

    Component.onCompleted: if (terms.length) cve.search(terms)

    SilicaListView {
        anchors.fill: parent
        model: cve.results

        header: Column {
            width: cvePage.width
            spacing: Theme.paddingMedium

            PageHeader { title: qsTr("Known CVEs") }

            SearchField {
                id: search
                width: parent.width
                text: cvePage.terms
                placeholderText: qsTr("Vendor + model")
                EnterKey.onClicked: { cvePage.terms = text; cve.search(text) }
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: cve.busy ? Theme.highlightColor : Theme.secondaryColor
                text: cve.status
            }
            BusyIndicator { running: cve.busy; anchors.horizontalCenter: parent.horizontalCenter }
        }

        delegate: ListItem {
            id: del
            width: ListView.view.width
            contentHeight: Theme.itemSizeLarge
            onClicked: Qt.openUrlExternally(modelData.url)

            menu: ContextMenu {
                MenuItem {
                    text: qsTr("Open on NVD")
                    onClicked: Qt.openUrlExternally(modelData.url)
                }
                MenuItem {
                    text: qsTr("Search Exploit-DB")
                    onClicked: Qt.openUrlExternally(modelData.exploitdb)
                }
            }

            Row {
                anchors {
                    left: parent.left; right: parent.right
                    leftMargin: Theme.horizontalPageMargin
                    rightMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }
                spacing: Theme.paddingMedium

                Rectangle {
                    anchors.verticalCenter: parent.verticalCenter
                    width: Theme.itemSizeExtraSmall * 0.9
                    height: width; radius: Theme.paddingSmall / 2
                    color: sevColor(modelData.severity)
                    Label {
                        anchors.centerIn: parent
                        text: modelData.score >= 0 ? ("" + modelData.score) : "?"
                        font.pixelSize: Theme.fontSizeSmall
                        font.bold: true; color: "white"
                    }
                }
                Column {
                    width: parent.width - Theme.itemSizeExtraSmall * 0.9 - Theme.paddingMedium
                    Row {
                        spacing: Theme.paddingSmall
                        Label {
                            text: modelData.id + "  ·  " + modelData.severity
                            font.pixelSize: Theme.fontSizeSmall
                            color: del.highlighted ? Theme.highlightColor : Theme.primaryColor
                        }
                        Label {
                            visible: modelData.kev === true
                            text: "⚠ KEV"
                            font.pixelSize: Theme.fontSizeSmall
                            font.bold: true
                            color: "#D32F2F"
                        }
                    }
                    Label {
                        width: parent.width
                        text: modelData.summary
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        wrapMode: Text.WordWrap
                        maximumLineCount: 2
                        truncationMode: TruncationMode.Elide
                    }
                }
            }
        }

        ViewPlaceholder {
            enabled: !cve.busy && cve.results.length === 0
            text: cve.status
        }
        VerticalScrollDecorator {}
    }
}
