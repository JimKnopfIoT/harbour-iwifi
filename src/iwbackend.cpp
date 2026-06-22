/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT
  Licensed under the GNU General Public License v3 or later.
*/
#include "iwbackend.h"

#include <QFile>
#include <QTextStream>
#include <QtMath>
#include <QSet>

#include <sailfishapp.h>

IwBackend::IwBackend(QObject *parent)
    : QObject(parent)
    , m_loaded(false)
{
}

QString IwBackend::normalizeHex(const QString &bssid)
{
    QString h;
    h.reserve(12);
    for (QChar c : bssid) {
        if (c.isLetterOrNumber() && QString("0123456789abcdefABCDEF").contains(c))
            h.append(c.toUpper());
    }
    return h;
}

void IwBackend::ensureLoaded()
{
    if (m_loaded)
        return;
    m_loaded = true; // attempt once; stay empty on failure

    const QString path = SailfishApp::pathTo(QStringLiteral("oui.tsv")).toLocalFile();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return;

    QSet<int> lengths;
    QTextStream in(&f);
    while (!in.atEnd()) {
        const QString line = in.readLine();
        if (line.isEmpty())
            continue;
        const int t1 = line.indexOf('\t');
        if (t1 <= 0)
            continue;
        const int t2 = line.indexOf('\t', t1 + 1);
        if (t2 <= t1)
            continue;
        const QString prefix = line.left(t1);
        const QString name = line.mid(t2 + 1);
        m_oui.insert(prefix, name);
        lengths.insert(prefix.length());
    }
    f.close();

    m_lengthsDesc = lengths.values();
    std::sort(m_lengthsDesc.begin(), m_lengthsDesc.end(), std::greater<int>());
}

bool IwBackend::isLocallyAdministered(const QString &bssid) const
{
    const QString h = normalizeHex(bssid);
    if (h.length() < 2)
        return false;
    bool ok = false;
    const int firstOctet = h.left(2).toInt(&ok, 16);
    return ok && (firstOctet & 0x02);
}

QString IwBackend::vendor(const QString &bssid)
{
    ensureLoaded();
    const QString h = normalizeHex(bssid);
    if (h.length() < 6)
        return QString();
    if (isLocallyAdministered(bssid))
        return QString(); // randomized / locally administered -> unknown vendor
    for (int len : m_lengthsDesc) {
        if (h.length() < len)
            continue;
        const QString key = h.left(len);
        auto it = m_oui.constFind(key);
        if (it != m_oui.constEnd())
            return aliasVendor(it.value());
    }
    return QString();
}

// Friendly/updated brand names overriding the raw IEEE registrant string.
QString IwBackend::aliasVendor(const QString &name)
{
    // AVM rebranded to "FRITZ!" in 2024; its OUI blocks register as "AVM ...".
    if (name.startsWith(QStringLiteral("AVM"), Qt::CaseInsensitive))
        return QStringLiteral("FRITZ!(AVM)");
    return name;
}

QString IwBackend::band(int freqMhz) const
{
    if (freqMhz >= 2400 && freqMhz < 2500)
        return QStringLiteral("2.4 GHz");
    if (freqMhz >= 4900 && freqMhz < 5900)
        return QStringLiteral("5 GHz");
    if (freqMhz >= 5925 && freqMhz <= 7125)
        return QStringLiteral("6 GHz");
    return QStringLiteral("?");
}

int IwBackend::channel(int freqMhz) const
{
    if (freqMhz == 2484)
        return 14;
    if (freqMhz >= 2412 && freqMhz <= 2472)
        return (freqMhz - 2407) / 5;
    if (freqMhz >= 5160 && freqMhz <= 5895)
        return (freqMhz - 5000) / 5;
    if (freqMhz >= 5955 && freqMhz <= 7115)
        return (freqMhz - 5950) / 5;
    return -1;
}

double IwBackend::distanceMeters(int strengthDbm, int freqMhz,
                                 double pathLossN, double txPowerDbm) const
{
    if (freqMhz <= 0 || strengthDbm >= 0)
        return -1.0;
    // Free-space path loss at 1 m reference distance:
    //   FSPL(1m) = 20*log10(f_MHz) - 27.55
    // Log-distance model: PL = FSPL(1m) + 10*n*log10(d)
    //   with PL = txPower - RSSI
    const double pl1m = 20.0 * std::log10((double)freqMhz) - 27.55;
    // Raw log-distance estimate for a given RSSI (metres, anchored at 1 m).
    const double n10 = 10.0 * pathLossN;
    auto raw = [&](double rssi) {
        return std::pow(10.0, ((txPowerDbm - rssi) - pl1m) / n10);
    };
    // Near-field anchor: a very strong signal means the phone is essentially on
    // top of the AP (the receiver AGC saturates around here, so a closer distance
    // can't be told apart). Call that 0 m and shift the whole curve down by the
    // model's prediction there, so adjacent APs read ~0 instead of ~1-2 m.
    const double nearFieldDbm = -40.0;
    const double d = raw((double)strengthDbm) - raw(nearFieldDbm);
    return d < 0.0 ? 0.0 : d;
}

QString IwBackend::securityLabel(const QStringList &security) const
{
    return classifySecurity(security).value(QStringLiteral("label")).toString();
}

QVariantMap IwBackend::classifySecurity(const QStringList &security) const
{
    // ConnMan (Sailfish) tokens: none/wep/psk/ieee8021x/sae/psksae (+wps/wps_advertising)
    QStringList s;
    for (const QString &t : security)
        s.append(t.toLower());

    const bool wps = s.contains(QStringLiteral("wps"))
            || s.contains(QStringLiteral("wps_advertising"));

    QString label;
    QString risk;    // good | ok | weak | critical
    if (s.contains(QStringLiteral("sae"))) {
        label = QStringLiteral("WPA3");
        risk = QStringLiteral("good");
    } else if (s.contains(QStringLiteral("psksae"))) {
        label = QStringLiteral("WPA2/WPA3");
        risk = QStringLiteral("good");
    } else if (s.contains(QStringLiteral("ieee8021x"))) {
        label = QStringLiteral("Enterprise (802.1X)");
        risk = QStringLiteral("good");
    } else if (s.contains(QStringLiteral("psk"))) {
        label = QStringLiteral("WPA2");
        risk = QStringLiteral("ok");
    } else if (s.contains(QStringLiteral("wep"))) {
        label = QStringLiteral("WEP");
        risk = QStringLiteral("critical");
    } else if (s.isEmpty() || s.contains(QStringLiteral("none"))) {
        label = QStringLiteral("Open");
        risk = QStringLiteral("critical");
    } else {
        label = security.join(QStringLiteral("/"));
        risk = QStringLiteral("weak");
    }

    QString color;
    if (risk == QStringLiteral("good"))        color = QStringLiteral("#4CAF50");
    else if (risk == QStringLiteral("ok"))     color = QStringLiteral("#8BC34A");
    else if (risk == QStringLiteral("weak"))   color = QStringLiteral("#FF9800");
    else                                       color = QStringLiteral("#F44336");

    QVariantMap m;
    m.insert(QStringLiteral("label"), label);
    m.insert(QStringLiteral("risk"), risk);
    m.insert(QStringLiteral("color"), color);
    m.insert(QStringLiteral("isWpa3"), s.contains(QStringLiteral("sae"))
             || s.contains(QStringLiteral("psksae")));
    m.insert(QStringLiteral("wps"), wps);
    return m;
}
