/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  App-gates the root monitor-mode sniffer: starts/stops the
  harbour-iwifi-monitor.service systemd unit over the system bus. A polkit rule
  (50-harbour-iwifi-monitor.rules) lets defaultuser manage just that one unit, so
  the sandboxed app can run the sniffer only while it is in the foreground and
  stop it on background/exit — the continuous monitor RX is what drains the
  battery, so it must never run unattended.
*/
#ifndef MONITORCTL_H
#define MONITORCTL_H

#include <QObject>

class MonitorControl : public QObject
{
    Q_OBJECT
public:
    explicit MonitorControl(QObject *parent = nullptr) : QObject(parent) {}

    // Start/stop the monitor-sniffer unit. Both are fire-and-forget; the UI
    // observes the actual capture through the Sniffer (the /tmp JSON freshness).
    Q_INVOKABLE void start();
    Q_INVOKABLE void stop();

signals:
    // emitted with a human-readable error if the D-Bus call fails outright
    void failed(const QString &message);

private:
    void callManager(const QString &method);
};

#endif // MONITORCTL_H
