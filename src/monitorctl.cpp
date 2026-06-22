/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "monitorctl.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCall>

void MonitorControl::start() { callManager(QStringLiteral("StartUnit")); }
void MonitorControl::stop()  { callManager(QStringLiteral("StopUnit")); }

void MonitorControl::callManager(const QString &method)
{
    QDBusMessage msg = QDBusMessage::createMethodCall(
        QStringLiteral("org.freedesktop.systemd1"),
        QStringLiteral("/org/freedesktop/systemd1"),
        QStringLiteral("org.freedesktop.systemd1.Manager"),
        method);
    // StartUnit(name, mode) / StopUnit(name, mode); "replace" = supersede any
    // queued job for the same unit.
    msg << QStringLiteral("harbour-iwifi-monitor.service")
        << QStringLiteral("replace");

    QDBusConnection bus = QDBusConnection::systemBus();
    if (!bus.isConnected()) {
        emit failed(tr("No system D-Bus"));
        return;
    }
    // fire-and-forget: the polkit rule authorises defaultuser for this one unit;
    // the UI observes the result via the sniffer JSON, not this reply.
    bus.asyncCall(msg);
}
