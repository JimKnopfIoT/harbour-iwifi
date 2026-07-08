/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "battery.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>

Battery::Battery(QObject *parent) : QObject(parent)
{
    resolvePaths();
    connect(&m_timer, &QTimer::timeout, this, &Battery::poll);
    m_timer.start(10000); // every 10 s is plenty for a battery gauge
    poll();
}

// Find the real battery power-supply node. The Xperia 10 III exposes
// /sys/class/power_supply/battery, but be defensive and scan for a supply
// whose `type` is "Battery" so this also works on other devices.
void Battery::resolvePaths()
{
    const QString base = QStringLiteral("/sys/class/power_supply");

    auto tryDir = [this](const QString &dir) -> bool {
        QFile cap(dir + "/capacity");
        if (!cap.exists())
            return false;
        m_capacityPath = dir + "/capacity";
        if (QFile::exists(dir + "/status"))
            m_statusPath = dir + "/status";
        return true;
    };

    // preferred name first
    if (tryDir(base + "/battery"))
        return;

    QDir d(base);
    const QStringList entries = d.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
    for (const QString &e : entries) {
        const QString dir = base + "/" + e;
        QFile t(dir + "/type");
        if (t.open(QIODevice::ReadOnly)) {
            const QByteArray type = t.readAll().trimmed();
            t.close();
            if (type == "Battery" && tryDir(dir))
                return;
        }
    }
}

void Battery::poll()
{
    int level = -1;
    bool charging = false;

    if (!m_capacityPath.isEmpty()) {
        QFile f(m_capacityPath);
        if (f.open(QIODevice::ReadOnly)) {
            bool ok = false;
            int v = f.readAll().trimmed().toInt(&ok);
            if (ok)
                level = v < 0 ? 0 : (v > 100 ? 100 : v);
            f.close();
        }
    }
    if (!m_statusPath.isEmpty()) {
        QFile f(m_statusPath);
        if (f.open(QIODevice::ReadOnly)) {
            const QByteArray s = f.readAll().trimmed();
            charging = (s == "Charging" || s == "Full");
            f.close();
        }
    }

    if (level != m_level || charging != m_charging) {
        m_level = level;
        m_charging = charging;
        emit changed();
    }
}
