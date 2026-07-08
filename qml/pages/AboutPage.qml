/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

Page {
    id: aboutPage

    SilicaFlickable {
        anchors.fill: parent
        anchors.bottomMargin: Theme.paddingLarge
        contentHeight: header.height + content.height

        PageHeader {
            id: header
            title: qsTr("About") + " iwifi"
        }

        Column {
            id: content
            anchors.top: header.bottom
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width - 2 * Theme.horizontalPageMargin
            spacing: Theme.paddingLarge

            Image {
                anchors.horizontalCenter: parent.horizontalCenter
                width: Theme.iconSizeExtraLarge
                height: Theme.iconSizeExtraLarge
                source: "../harbour-iwifi.png"
            }

            Label {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "v1.0.0"
            }

            Label {
                width: parent.width
                horizontalAlignment: Text.AlignHCenter
                text: "© 2026 JimKnopfIoT"
            }

            Label {
                width: parent.width
                wrapMode: Text.WordWrap
                text: qsTr("A WiFi scanner & security checker for Sailfish OS — signal, channels, security, vendors, LAN devices and router CVEs. Distributed under the GNU GPLv3.")
            }

        }

        VerticalScrollDecorator {
        }
    }
}
