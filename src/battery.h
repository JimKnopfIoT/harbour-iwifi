/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Tiny battery monitor: polls /sys/class/power_supply for the battery's charge
  level and charging state and exposes them to QML, so a persistent indicator
  can be shown on every view (the external monitor adapter drains the phone
  fast, so the user needs to see the level at all times).
*/
#ifndef BATTERY_H
#define BATTERY_H

#include <QObject>
#include <QString>
#include <QTimer>

class Battery : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int level READ level NOTIFY changed)        // 0..100, -1 = unknown
    Q_PROPERTY(bool charging READ charging NOTIFY changed)
public:
    explicit Battery(QObject *parent = nullptr);

    int level() const { return m_level; }
    bool charging() const { return m_charging; }

signals:
    void changed();

private slots:
    void poll();

private:
    QString m_capacityPath;   // resolved sysfs path to .../capacity
    QString m_statusPath;     // resolved sysfs path to .../status
    int m_level = -1;
    bool m_charging = false;
    QTimer m_timer;

    void resolvePaths();
};

#endif // BATTERY_H
