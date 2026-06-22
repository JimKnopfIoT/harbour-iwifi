/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Per-BSS scanner via wpa_supplicant's system D-Bus API
  (fi.w1.wpa_supplicant1). This works from inside the Sailjail sandbox (D-Bus
  crosses it, like ConnMan) whereas `iw`/nl80211 does not (the sandbox's
  `net none` hides wlan0). Needs:
    - a D-Bus policy granting the app's user access to fi.w1.wpa_supplicant1
    - a Sailjail permission with `dbus-system.talk fi.w1.wpa_supplicant1`
  Exposes the same `aps` list shape as the old iw-based backend.
*/
#ifndef WPASCAN_H
#define WPASCAN_H

#include <QObject>
#include <QVariantList>
#include <QVariantMap>
#include <QHash>
#include <QString>
#include <QTimer>

class WpaScan : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList aps READ aps NOTIFY updated)
    Q_PROPERTY(int count READ count NOTIFY updated)
public:
    explicit WpaScan(QObject *parent = nullptr);

    QVariantList aps() const { return m_aps; }
    int count() const { return m_aps.size(); }

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void start(int intervalMs = 2500);
    Q_INVOKABLE void stop();

signals:
    void updated();

private:
    QString interfacePath();
    QVariantMap readBss(const QString &path);
    static QString secLabelFromKeyMgmt(const QStringList &km, QString &risk, bool &wpa3);
    static void parseIes(const QByteArray &ies, QVariantMap &rec);
    static void parseWps(const unsigned char *p, int n, QVariantMap &rec);

    QVariantList m_aps;
    QHash<QString, QVariantMap> m_seen;
    int m_gen;
    QString m_ifPath;
    QTimer *m_timer;
};

#endif // WPASCAN_H
