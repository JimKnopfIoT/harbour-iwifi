/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT
  Licensed under the GNU General Public License v3 or later.

  Tier-1 backend helpers: OUI vendor lookup, RSSI distance estimate,
  security classification, frequency -> band/channel.
*/
#ifndef IWBACKEND_H
#define IWBACKEND_H

#include <QObject>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVariantMap>

class IwBackend : public QObject
{
    Q_OBJECT
public:
    explicit IwBackend(QObject *parent = nullptr);

    // OUI / vendor
    Q_INVOKABLE QString vendor(const QString &bssid);
    Q_INVOKABLE bool isLocallyAdministered(const QString &bssid) const;

    // RF helpers
    Q_INVOKABLE QString band(int freqMhz) const;
    Q_INVOKABLE int channel(int freqMhz) const;

    // Distance estimate (log-distance path loss). strengthDbm is negative dBm.
    // Defaults fitted to four laser-measured ground-truth points: a router at
    // 2.5 m (-42@2437, -45@5260, -50@5745) and a repeater at 6 m (-62@5260).
    // Least-squares gives txPower ~14.3 dBm, n ~3.78 (high indoor path-loss
    // exponent, walls). Both tunable (future settings).
    Q_INVOKABLE double distanceMeters(int strengthDbm, int freqMhz,
                                      double pathLossN = 3.78,
                                      double txPowerDbm = 14.3) const;

    // Security: returns { label, risk, color, isWpa3, wps }
    Q_INVOKABLE QVariantMap classifySecurity(const QStringList &security) const;
    Q_INVOKABLE QString securityLabel(const QStringList &security) const;

private:
    void ensureLoaded();
    static QString normalizeHex(const QString &bssid);
    static QString aliasVendor(const QString &name);

    QHash<QString, QString> m_oui;   // hex prefix (variable length) -> vendor
    QList<int> m_lengthsDesc;        // distinct prefix nibble-lengths, descending
    bool m_loaded;
};

#endif // IWBACKEND_H
