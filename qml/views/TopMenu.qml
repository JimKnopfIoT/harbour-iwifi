/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

PullDownMenu {
    property string pageName

    MenuItem {
        text: qsTr("About")
        onClicked: pageContainer.push(Qt.resolvedUrl("../pages/AboutPage.qml"))
    }
    MenuItem {
        text: qsTr("Channel analysis")
        onClicked: pageContainer.push(Qt.resolvedUrl("../pages/ChannelPage.qml"))
    }
    MenuItem {
        text: qsTr("LAN devices (ARP)")
        onClicked: pageContainer.push(Qt.resolvedUrl("../pages/ClientsPage.qml"))
    }
}
