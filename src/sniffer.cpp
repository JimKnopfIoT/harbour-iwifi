/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "sniffer.h"

#include <QTimer>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

// Shared snapshot path. The iwsniff root helper writes here; the sandbox is
// granted read access to it. Considered "live" if rewritten within 15 s.
static const char *SNIFF_PATH = "/tmp/iwifi-sniff.json";
static const qint64 FRESH_MS = 15000;

Sniffer::Sniffer(QObject *parent)
    : QObject(parent)
    , m_path(QString::fromLatin1(SNIFF_PATH))
    , m_mtime(0)
    , m_available(false)
    , m_timer(new QTimer(this))
{
    connect(m_timer, &QTimer::timeout, this, &Sniffer::poll);
    m_timer->start(2000);
    poll();
}

void Sniffer::poll()
{
    QFileInfo fi(m_path);
    const bool fresh = fi.exists()
            && fi.lastModified().msecsTo(QDateTime::currentDateTime()) < FRESH_MS;

    if (!fresh) {
        if (m_available) {
            m_available = false;
            emit changed();
        }
        return;
    }

    const qint64 mt = fi.lastModified().toMSecsSinceEpoch();
    if (mt == m_mtime && m_available)
        return;                       // unchanged since last parse
    m_mtime = mt;

    QFile f(m_path);
    if (!f.open(QIODevice::ReadOnly))
        return;
    const QJsonObject root = QJsonDocument::fromJson(f.readAll()).object();
    f.close();

    // Per-AP records only. Each carries an associated-client COUNT (an integer);
    // there are no per-client objects to read (privacy by construction).
    QVariantList aps;
    m_count.clear();
    const QJsonArray ja = root.value("aps").toArray();
    for (const QJsonValue &v : ja) {
        const QVariantMap a = v.toObject().toVariantMap();
        aps.append(a);
        const QString b = a.value("bssid").toString().toUpper();
        if (!b.isEmpty())
            m_count.insert(b, a.value("clients").toInt());
    }
    m_aps = aps;

    m_available = true;
    emit changed();
}

int Sniffer::clientCount(const QString &bssid) const
{
    return m_count.value(bssid.toUpper());
}

QVariantMap Sniffer::apForBssid(const QString &bssid) const
{
    const QString b = bssid.toUpper();
    for (const QVariant &v : m_aps) {
        const QVariantMap a = v.toMap();
        if (a.value("bssid").toString().toUpper() == b)
            return a;
    }
    return QVariantMap();
}
