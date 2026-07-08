/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "wpascan.h"

#include <QtDBus>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDBusObjectPath>
#include <QDBusArgument>
#include <QDBusVariant>

static const char *SERVICE = "fi.w1.wpa_supplicant1";

static QVariant getProp(const QString &path, const QString &iface, const QString &name)
{
    QDBusInterface props(SERVICE, path, "org.freedesktop.DBus.Properties",
                         QDBusConnection::systemBus());
    QDBusReply<QDBusVariant> r = props.call("Get", iface, name);
    if (!r.isValid())
        return QVariant();
    return r.value().variant();
}

static QStringList toStringList(const QVariant &v)
{
    if (v.canConvert<QStringList>())
        return v.toStringList();
    if (v.canConvert<QDBusArgument>())
        return qdbus_cast<QStringList>(v.value<QDBusArgument>());
    return QStringList();
}

static QVariantMap toMap(const QVariant &v)
{
    if (v.canConvert<QVariantMap>())
        return v.toMap();
    if (v.canConvert<QDBusArgument>())
        return qdbus_cast<QVariantMap>(v.value<QDBusArgument>());
    return QVariantMap();
}

static QByteArray toBytes(const QVariant &v)
{
    if (v.type() == QVariant::ByteArray)
        return v.toByteArray();
    if (v.canConvert<QDBusArgument>())
        return qdbus_cast<QByteArray>(v.value<QDBusArgument>());
    return v.toByteArray();
}

static QString macFromBytes(const QByteArray &b)
{
    QStringList parts;
    for (int i = 0; i < b.size(); ++i)
        parts << QString("%1").arg((quint8)b.at(i), 2, 16, QChar('0')).toUpper();
    return parts.join(':');
}

static int strengthFromDbm(int dbm)
{
    int s = 2 * (dbm + 100);
    return s < 0 ? 0 : (s > 100 ? 100 : s);
}

WpaScan::WpaScan(QObject *parent)
    : QObject(parent)
    , m_gen(0)
    , m_timer(new QTimer(this))
{
    connect(m_timer, &QTimer::timeout, this, &WpaScan::refresh);
}

void WpaScan::start(int intervalMs)
{
    refresh();
    m_timer->start(intervalMs);
}

void WpaScan::stop()
{
    m_timer->stop();
}

QString WpaScan::interfacePath()
{
    if (!m_ifPath.isEmpty())
        return m_ifPath;
    QVariant v = getProp("/fi/w1/wpa_supplicant1", "fi.w1.wpa_supplicant1", "Interfaces");
    QList<QDBusObjectPath> ifs;
    if (v.canConvert<QDBusArgument>())
        ifs = qdbus_cast<QList<QDBusObjectPath> >(v.value<QDBusArgument>());
    if (ifs.isEmpty())
        return m_ifPath;
    // Prefer the built-in station interface (wlan0). An external monitor adapter
    // (e.g. the Alfa as wlan1) also registers with wpa_supplicant but, in monitor
    // mode, carries no BSSs — picking it would empty the whole network list.
    for (const QDBusObjectPath &p : ifs) {
        const QString name = getProp(p.path(),
                                     "fi.w1.wpa_supplicant1.Interface", "Ifname").toString();
        if (name == QStringLiteral("wlan0")) {
            m_ifPath = p.path();   // cache only the real one
            return m_ifPath;
        }
    }
    return ifs.first().path();      // fallback, uncached -> retry until wlan0 shows
}

QString WpaScan::secLabelFromKeyMgmt(const QStringList &km, QString &risk, bool &wpa3)
{
    wpa3 = false;
    bool sae = false, psk = false, eap = false;
    for (const QString &k : km) {
        const QString s = k.toLower();
        if (s.contains("sae")) sae = true;
        else if (s.contains("psk")) psk = true;
        if (s.contains("eap")) eap = true;
    }
    if (sae && psk) { risk = "good"; wpa3 = true; return "WPA2/WPA3"; }
    if (sae)        { risk = "good"; wpa3 = true; return "WPA3"; }
    if (eap)        { risk = "good"; return "Enterprise"; }
    if (psk)        { risk = "ok"; return "WPA2"; }
    risk = "weak";
    return "WPA";
}

void WpaScan::parseWps(const unsigned char *p, int n, QVariantMap &rec)
{
    rec.insert("wps", true);
    int i = 0;
    while (i + 4 <= n) {
        const int t = (p[i] << 8) | p[i + 1];
        const int l = (p[i + 2] << 8) | p[i + 3];
        if (i + 4 + l > n)
            break;
        const QString val = QString::fromLatin1((const char *)(p + i + 4), l);
        switch (t) {
        case 0x1021: rec.insert("manufacturer", val); break;
        case 0x1023: rec.insert("model", val); break;
        case 0x1024: rec.insert("modelNumber", val); break;
        case 0x1011: rec.insert("deviceName", val); break;
        case 0x1042: rec.insert("serial", val); break;
        default: break;
        }
        i += 4 + l;
    }
}

void WpaScan::parseIes(const QByteArray &ies, QVariantMap &rec)
{
    const unsigned char *d = (const unsigned char *)ies.constData();
    const int n = ies.size();
    bool htOp = false, vhtOp = false, heOp = false;
    int width = 20;
    int i = 0;
    while (i + 2 <= n) {
        const int type = d[i];
        const int len = d[i + 1];
        if (i + 2 + len > n)
            break;
        const unsigned char *v = d + i + 2;
        if (type == 61 && len >= 2) {            // HT Operation
            htOp = true;
            const int off = v[1] & 0x03;         // secondary channel offset
            if (off == 1 || off == 3)
                width = 40;
        } else if (type == 45) {                 // HT Capabilities
            htOp = true;
        } else if (type == 192 && len >= 1) {    // VHT Operation
            vhtOp = true;
            if (v[0] == 1) width = 80;
            else if (v[0] == 2 || v[0] == 3) width = 160;
        } else if (type == 255 && len >= 1 && v[0] == 36) { // HE Operation (ext)
            heOp = true;
        } else if (type == 221 && len >= 4 &&
                   v[0] == 0x00 && v[1] == 0x50 && v[2] == 0xF2 && v[3] == 0x04) {
            parseWps(v + 4, len - 4, rec);       // WPS vendor IE
        } else if (type == 11 && len >= 3) {     // BSS Load: stations + utilization
            rec.insert("bssStations", v[0] | (v[1] << 8));
            rec.insert("bssUtil", (v[2] * 100) / 255);
        } else if (type == 7 && len >= 2) {      // Country / regulatory domain
            rec.insert("country", QString::fromLatin1((const char *)v, 2).trimmed());
        } else if (type == 48 && len >= 8) {     // RSN -> Management Frame Protection
            int p = 2 + 4;                        // skip version + group cipher
            int pc = v[p] | (v[p + 1] << 8); p += 2 + pc * 4;       // pairwise list
            if (p + 2 <= len) {
                int ac = v[p] | (v[p + 1] << 8); p += 2 + ac * 4;   // AKM list
                if (p + 2 <= len) {
                    const int cap = v[p] | (v[p + 1] << 8);
                    rec.insert("pmf", (cap & 0x40) ? "required"
                                      : ((cap & 0x80) ? "optional" : "off"));
                }
            }
        }
        i += 2 + len;
    }

    const int freq = rec.value("frequency").toInt();
    QString phy;
    if (heOp) phy = "ax";
    else if (vhtOp) phy = "ac";
    else if (htOp) phy = "n";
    else phy = (freq < 2500) ? "g" : "a";
    rec.insert("phy", phy);
    rec.insert("chWidth", width);
}

QVariantMap WpaScan::readBss(const QString &path)
{
    QDBusInterface props(SERVICE, path, "org.freedesktop.DBus.Properties",
                         QDBusConnection::systemBus());
    QDBusReply<QVariantMap> reply = props.call("GetAll", "fi.w1.wpa_supplicant1.BSS");
    if (!reply.isValid())
        return QVariantMap();
    const QVariantMap m = reply.value();
    if (m.isEmpty())
        return QVariantMap();

    QVariantMap rec;
    rec.insert("bssid", macFromBytes(toBytes(m.value("BSSID"))));
    rec.insert("ssid", QString::fromUtf8(toBytes(m.value("SSID"))));
    rec.insert("frequency", m.value("Frequency").toInt());
    const int signal = m.value("Signal").toInt();
    rec.insert("signal", signal);
    rec.insert("strength", strengthFromDbm(signal));

    // security from RSN / WPA key management
    const QVariantMap rsn = toMap(m.value("RSN"));
    const QVariantMap wpa = toMap(m.value("WPA"));
    const QStringList rsnKm = toStringList(rsn.value("KeyMgmt"));
    const QStringList wpaKm = toStringList(wpa.value("KeyMgmt"));
    QString label, risk;
    bool wpa3 = false;
    if (!rsnKm.isEmpty()) {
        label = secLabelFromKeyMgmt(rsnKm, risk, wpa3);
    } else if (!wpaKm.isEmpty()) {
        label = "WPA"; risk = "weak";
    } else if (m.value("Privacy").toBool()) {
        label = "WEP"; risk = "critical";
    } else {
        label = "Open"; risk = "critical";
    }
    rec.insert("security", label);
    rec.insert("secRisk", risk);
    rec.insert("isWpa3", wpa3);

    // pairwise cipher (CCMP/GCMP good, TKIP weak), hidden SSID
    QStringList pw = toStringList(rsn.value("Pairwise"));
    if (pw.isEmpty()) pw = toStringList(wpa.value("Pairwise"));
    rec.insert("cipher", pw.join("/").toUpper());
    rec.insert("hidden", rec.value("ssid").toString().isEmpty());

    // defaults for IE-derived fields (filled in parseIes if present)
    rec.insert("pmf", QString());
    rec.insert("bssStations", -1);
    rec.insert("bssUtil", -1);
    rec.insert("country", QString());

    // defaults, then IE parse (fills wps/model/phy/chWidth)
    rec.insert("wps", false);
    rec.insert("manufacturer", QString());
    rec.insert("model", QString());
    rec.insert("deviceName", QString());
    rec.insert("serial", QString());
    parseIes(toBytes(m.value("IEs")), rec);
    return rec;
}

void WpaScan::refresh()
{
    const QString ifp = interfacePath();
    if (ifp.isEmpty())
        return;
    QVariant v = getProp(ifp, "fi.w1.wpa_supplicant1.Interface", "BSSs");
    QList<QDBusObjectPath> bsss;
    if (v.canConvert<QDBusArgument>())
        bsss = qdbus_cast<QList<QDBusObjectPath> >(v.value<QDBusArgument>());

    ++m_gen;
    for (const QDBusObjectPath &p : bsss) {
        QVariantMap rec = readBss(p.path());
        if (rec.isEmpty())
            continue;
        rec.insert("_gen", m_gen);
        m_seen.insert(rec.value("bssid").toString(), rec);
    }
    const int KEEP = 6;
    QVariantList result;
    for (auto it = m_seen.begin(); it != m_seen.end(); ) {
        if (m_gen - it.value().value("_gen").toInt() <= KEEP) {
            result.append(it.value());
            ++it;
        } else {
            it = m_seen.erase(it);
        }
    }
    m_aps = result;
    emit updated();
}
