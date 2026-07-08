/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Clients on the CONNECTED network (Tier 2). Reads the kernel ARP cache; an
  active scan does a quick TCP sweep of the /24 to discover more hosts. Only the
  joined network is reachable — foreign APs' clients can't be seen.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

import "../views"

Page {
    id: clientsPage

    Component.onCompleted: lan.refresh()

    SilicaListView {
        anchors.fill: parent
        model: lan.hosts

        PullDownMenu {
            MenuItem {
                text: qsTr("Active scan (find more)")
                onClicked: lan.sweep()
            }
            MenuItem {
                text: qsTr("Refresh")
                onClicked: lan.refresh()
            }
        }

        header: Column {
            width: clientsPage.width
            spacing: Theme.paddingSmall

            PageHeader { title: qsTr("Network devices") }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.secondaryColor
                text: lan.subnet.length
                      ? qsTr("Network %1 · %2 device(s)").arg(lan.subnet).arg(lan.count)
                      : qsTr("Not connected to a network")
            }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WordWrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("From the ARP table — ALL devices on the subnet, wired and Wi‑Fi alike (L3 can't tell them apart). True Wi‑Fi clients need the router API (TR‑064) or monitor mode.")
            }
            BusyIndicator {
                running: lan.busy
                anchors.horizontalCenter: parent.horizontalCenter
            }
            Label {
                visible: lan.busy
                anchors.horizontalCenter: parent.horizontalCenter
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: qsTr("scanning the subnet…")
            }
        }

        delegate: ListItem {
            id: del
            width: ListView.view.width
            contentHeight: Theme.itemSizeMedium

            Row {
                anchors {
                    left: parent.left; right: parent.right
                    leftMargin: Theme.horizontalPageMargin
                    rightMargin: Theme.horizontalPageMargin
                    verticalCenter: parent.verticalCenter
                }
                spacing: Theme.paddingMedium

                WifiIcon {
                    anchors.verticalCenter: parent.verticalCenter
                    width: Theme.itemSizeExtraSmall
                    height: width
                    shape: modelData.gateway ? "circle" : "triangle"
                    fg: modelData.gateway ? Theme.highlightColor
                        : (modelData.self ? Theme.secondaryHighlightColor : Theme.primaryColor)
                }

                Column {
                    width: parent.width - Theme.itemSizeExtraSmall - Theme.paddingMedium
                    Row {
                        spacing: Theme.paddingSmall
                        Label {
                            text: modelData.ip
                            font.pixelSize: Theme.fontSizeMedium
                            color: del.highlighted ? Theme.highlightColor : Theme.primaryColor
                        }
                        Label {
                            visible: modelData.gateway === true
                            text: qsTr("router")
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.highlightColor
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: Theme.paddingSmall
                        }
                        Label {
                            visible: modelData.self === true
                            text: qsTr("this device")
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryHighlightColor
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: Theme.paddingSmall
                        }
                    }
                    Label {
                        width: parent.width
                        text: (modelData.mac && modelData.mac.length ? modelData.mac : qsTr("(this device)"))
                              + (modelData.mac && modelData.mac.length
                                 ? "  ·  " + iw.vendor(modelData.mac) : "")
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: Theme.secondaryColor
                        truncationMode: TruncationMode.Fade
                    }
                }
            }
        }

        ViewPlaceholder {
            enabled: !lan.busy && lan.count === 0
            text: qsTr("No clients")
            hintText: qsTr("Pull down → Active scan")
        }
        VerticalScrollDecorator {}
    }
}
