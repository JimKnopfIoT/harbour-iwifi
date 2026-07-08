/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "iwscan.h"

#include <QStringList>
#include <QtMath>
#include <QDebug>

IwScan::IwScan(QObject *parent)
    : QObject(parent)
    , m_gen(0)
    , m_proc(new QProcess(this))
    , m_timer(new QTimer(this))
    , m_busy(false)
{
    connect(m_proc, SIGNAL(finished(int, QProcess::ExitStatus)),
            this, SLOT(onFinished(int, QProcess::ExitStatus)));
    connect(m_proc, &QProcess::errorOccurred, this, [](QProcess::ProcessError e) {
        qWarning() << "IWIFI iwscan QProcess error:" << e;
    });
    connect(m_timer, &QTimer::timeout, this, &IwScan::refresh);
}

void IwScan::start(int intervalMs)
{
    refresh();
    m_timer->start(intervalMs);
}

void IwScan::stop()
{
    m_timer->stop();
}

void IwScan::refresh()
{
    if (m_proc->state() != QProcess::NotRunning)
        return;
    m_busy = true;
    emit busyChanged();
    m_proc->start(QStringLiteral("/usr/sbin/iw"),
                  QStringList() << QStringLiteral("dev")
                                << QStringLiteral("wlan0")
                                << QStringLiteral("scan") << QStringLiteral("dump"));
}

void IwScan::onFinished(int code, QProcess::ExitStatus status)
{
    Q_UNUSED(code)
    Q_UNUSED(status)
    const QString out = QString::fromUtf8(m_proc->readAllStandardOutput());
    const QString err = QString::fromUtf8(m_proc->readAllStandardError());
    qWarning() << "IWIFI iwscan finished code=" << code << "status=" << status
               << "outLen=" << out.length() << "err=" << err.left(120);
    parse(out);
    qWarning() << "IWIFI iwscan parsed aps=" << m_aps.size();
    m_busy = false;
    emit busyChanged();
}

static int strengthFromDbm(int dbm)
{
    int s = 2 * (dbm + 100);
    if (s < 0) s = 0;
    if (s > 100) s = 100;
    return s;
}

void IwScan::parse(const QString &out)
{
    QVariantList list;
    QVariantMap cur;
    bool have = false;

    // per-BSS accumulators
    bool htOp = false, vhtOp = false, heOp = false, has40 = false;
    bool rsn = false, wpa = false, privacy = false;
    QString auth;
    int vhtWidth = 0;

    auto finalize = [&]() {
        if (!have)
            return;
        // security
        QString label, risk;
        bool wpa3 = false;
        if (rsn) {
            const bool sae = auth.contains("SAE", Qt::CaseInsensitive);
            const bool psk = auth.contains("PSK", Qt::CaseInsensitive);
            const bool eap = auth.contains("802.1X", Qt::CaseInsensitive)
                    || auth.contains("EAP", Qt::CaseInsensitive);
            if (sae && psk) { label = "WPA2/WPA3"; risk = "good"; wpa3 = true; }
            else if (sae)   { label = "WPA3"; risk = "good"; wpa3 = true; }
            else if (eap)   { label = "Enterprise"; risk = "good"; }
            else            { label = "WPA2"; risk = "ok"; }
        } else if (wpa) {
            label = "WPA"; risk = "weak";
        } else if (privacy) {
            label = "WEP"; risk = "critical";
        } else {
            label = "Open"; risk = "critical";
        }
        cur.insert(QStringLiteral("security"), label);
        cur.insert(QStringLiteral("secRisk"), risk);
        cur.insert(QStringLiteral("isWpa3"), wpa3);
        if (!cur.contains(QStringLiteral("wps")))
            cur.insert(QStringLiteral("wps"), false);

        // phy generation
        const int freq = cur.value(QStringLiteral("frequency")).toInt();
        QString phy;
        if (heOp) phy = "ax";
        else if (vhtOp) phy = "ac";
        else if (htOp) phy = "n";
        else phy = (freq < 2500) ? "g" : "a";
        cur.insert(QStringLiteral("phy"), phy);

        // channel width
        int width = 20;
        if (vhtWidth > 0) width = vhtWidth;
        else if (has40) width = 40;
        cur.insert(QStringLiteral("chWidth"), width);

        cur.insert(QStringLiteral("strength"),
                   strengthFromDbm(cur.value(QStringLiteral("signal")).toInt()));

        // defaults for WPS text
        if (!cur.contains(QStringLiteral("manufacturer"))) cur.insert(QStringLiteral("manufacturer"), QString());
        if (!cur.contains(QStringLiteral("model"))) cur.insert(QStringLiteral("model"), QString());
        if (!cur.contains(QStringLiteral("deviceName"))) cur.insert(QStringLiteral("deviceName"), QString());
        if (!cur.contains(QStringLiteral("serial"))) cur.insert(QStringLiteral("serial"), QString());

        list.append(cur);
    };

    const QStringList lines = out.split('\n');
    for (const QString &raw : lines) {
        const QString line = raw.trimmed();
        if (raw.startsWith(QStringLiteral("BSS "))) {
            finalize();
            cur.clear();
            have = true;
            htOp = vhtOp = heOp = has40 = rsn = wpa = privacy = false;
            auth.clear();
            vhtWidth = 0;
            QString mac = raw.mid(4).section('(', 0, 0).trimmed();
            cur.insert(QStringLiteral("bssid"), mac.toUpper());
            cur.insert(QStringLiteral("ssid"), QString());
            cur.insert(QStringLiteral("frequency"), 0);
            cur.insert(QStringLiteral("signal"), -100);
        } else if (line.startsWith(QStringLiteral("freq:"))) {
            cur.insert(QStringLiteral("frequency"), line.mid(5).trimmed().toInt());
        } else if (line.startsWith(QStringLiteral("signal:"))) {
            cur.insert(QStringLiteral("signal"),
                       (int)qRound(line.mid(7).trimmed().section(' ', 0, 0).toDouble()));
        } else if (line.startsWith(QStringLiteral("SSID:"))) {
            cur.insert(QStringLiteral("ssid"), line.mid(5).trimmed());
        } else if (line.startsWith(QStringLiteral("RSN:"))) {
            rsn = true;
        } else if (line.startsWith(QStringLiteral("WPA:"))) {
            wpa = true;
        } else if (line.startsWith(QStringLiteral("HT operation:"))) {
            htOp = true;
        } else if (line.startsWith(QStringLiteral("VHT operation:"))) {
            vhtOp = true;
        } else if (line.startsWith(QStringLiteral("HE Operation:")) || line.startsWith(QStringLiteral("HE capabilities:"))) {
            heOp = true;
        } else if (line.contains(QStringLiteral("Authentication suites:"))) {
            auth += QLatin1Char(' ') + line.section(QStringLiteral("Authentication suites:"), 1, 1);
        } else if (line.contains(QStringLiteral("secondary channel offset:"))) {
            const QString v = line.section(':', 1, 1).trimmed();
            if (v == QStringLiteral("above") || v == QStringLiteral("below"))
                has40 = true;
        } else if (line.startsWith(QStringLiteral("* channel width:")) && vhtOp && vhtWidth == 0) {
            if (line.contains(QStringLiteral("160 MHz"))) vhtWidth = 160;
            else if (line.contains(QStringLiteral("80 MHz"))) vhtWidth = 80;
        } else if (line.startsWith(QStringLiteral("capability:"))) {
            if (line.contains(QStringLiteral("Privacy"))) privacy = true;
        } else if (line.startsWith(QStringLiteral("* Manufacturer:"))) {
            cur.insert(QStringLiteral("manufacturer"), line.mid(15).trimmed());
        } else if (line.startsWith(QStringLiteral("* Model:"))) {
            cur.insert(QStringLiteral("model"), line.mid(8).trimmed());
        } else if (line.startsWith(QStringLiteral("* Device name:"))) {
            cur.insert(QStringLiteral("deviceName"), line.mid(14).trimmed());
        } else if (line.startsWith(QStringLiteral("* Serial Number:"))) {
            cur.insert(QStringLiteral("serial"), line.mid(16).trimmed());
        } else if (line.startsWith(QStringLiteral("WPS:"))) {
            cur.insert(QStringLiteral("wps"), true);
        }
    }
    finalize();

    // Merge this (possibly partial) dump into an aged set so APs don't flicker
    // when a single scan pass misses some of them.
    ++m_gen;
    for (const QVariant &v : list) {
        QVariantMap r = v.toMap();
        r.insert(QStringLiteral("_gen"), m_gen);
        m_seen.insert(r.value(QStringLiteral("bssid")).toString(), r);
    }
    const int KEEP = 6; // ~15 s at a 2.5 s interval
    QVariantList result;
    for (auto it = m_seen.begin(); it != m_seen.end(); ) {
        if (m_gen - it.value().value(QStringLiteral("_gen")).toInt() <= KEEP) {
            result.append(it.value());
            ++it;
        } else {
            it = m_seen.erase(it);
        }
    }

    m_aps = result;
    emit updated();
}
