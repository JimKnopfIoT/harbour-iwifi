/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

CoverBackground {
    // faint oversized app-icon watermark behind the cover content
    Image {
        anchors.centerIn: parent
        source: "/usr/share/icons/hicolor/172x172/apps/harbour-iwifi.png"
        sourceSize { width: 172; height: 172 }
        width: parent.width * 1.5
        height: width
        fillMode: Image.PreserveAspectFit
        opacity: 0.12
        smooth: true
        asynchronous: true
    }

    Column {
        anchors.centerIn: parent
        visible: networksList.powered
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            font.bold: true
            font.pixelSize: Theme.fontSizeHuge
            text: iwscan.count
        }
        Label {
            anchors.horizontalCenter: parent.horizontalCenter
            text: qsTr("WiFi networks")
        }
    }

    Label {
        anchors.fill: parent
        anchors.margins: Theme.paddingSmall
        horizontalAlignment: Text.AlignHCenter
        verticalAlignment: Text.AlignVCenter
        wrapMode: Text.Wrap
        visible: !networksList.powered
        text: qsTr("WiFi is off")
    }
}
