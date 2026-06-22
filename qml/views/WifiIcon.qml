/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  A WiFi glyph drawn inside a shape:
    shape "circle"   -> access point
    shape "triangle" -> client / station (used later in Tier 2)
*/
import QtQuick 2.2
import Sailfish.Silica 1.0

Item {
    id: root

    property string shape: "circle"
    property color bg: Theme.rgba(Theme.highlightBackgroundColor, 0.3)
    property color fg: Theme.highlightColor

    width: Theme.itemSizeLarge
    height: width

    Canvas {
        id: cv
        anchors.fill: parent
        onPaint: {
            var ctx = getContext("2d")
            ctx.reset()
            var w = width, h = height, cx = w / 2

            ctx.fillStyle = root.bg
            if (root.shape === "triangle") {
                ctx.beginPath()
                ctx.moveTo(cx, h * 0.06)
                ctx.lineTo(w * 0.94, h * 0.92)
                ctx.lineTo(w * 0.06, h * 0.92)
                ctx.closePath()
                ctx.fill()
            } else {
                ctx.beginPath()
                ctx.arc(cx, h / 2, w * 0.46, 0, 2 * Math.PI)
                ctx.fill()
            }

            // wifi fan (pointing up)
            var oy = root.shape === "triangle" ? h * 0.66 : h * 0.60
            ctx.strokeStyle = root.fg
            ctx.lineWidth = Math.max(2, w * 0.05)
            ctx.lineCap = "round"
            for (var i = 1; i <= 3; ++i) {
                ctx.beginPath()
                ctx.arc(cx, oy, w * 0.12 * i, Math.PI * 1.25, Math.PI * 1.75)
                ctx.stroke()
            }
            ctx.fillStyle = root.fg
            ctx.beginPath()
            ctx.arc(cx, oy, w * 0.035, 0, 2 * Math.PI)
            ctx.fill()
        }
        Component.onCompleted: requestPaint()
        onWidthChanged: requestPaint()
        onHeightChanged: requestPaint()
    }
}
