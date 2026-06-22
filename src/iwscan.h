/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Per-BSS scanner backed by `iw dev wlan0 scan dump` (works as a normal user;
  reads the kernel's cached scan results). Unlike ConnMan it lists every BSS
  separately (router + repeater + bands) and exposes the IEs ConnMan hides:
  WPS manufacturer/model/device/serial, channel width (HT/VHT/HE), the real
  RSN cipher/auth (WPA2 vs WPA3), and the real signal in dBm.
*/
#ifndef IWSCAN_H
#define IWSCAN_H

#include <QObject>
#include <QVariantList>
#include <QVariantMap>
#include <QHash>
#include <QProcess>
#include <QTimer>
#include <QString>

class IwScan : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList aps READ aps NOTIFY updated)
    Q_PROPERTY(int count READ count NOTIFY updated)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
public:
    explicit IwScan(QObject *parent = nullptr);

    QVariantList aps() const { return m_aps; }
    int count() const { return m_aps.size(); }
    bool busy() const { return m_busy; }

    Q_INVOKABLE void refresh();             // run one `iw scan dump`
    Q_INVOKABLE void start(int intervalMs = 2500);
    Q_INVOKABLE void stop();

signals:
    void updated();
    void busyChanged();

private slots:
    void onFinished(int code, QProcess::ExitStatus status);

private:
    void parse(const QString &out);

    QVariantList m_aps;
    QHash<QString, QVariantMap> m_seen;   // aged set, keyed by BSSID
    int m_gen;
    QProcess *m_proc;
    QTimer *m_timer;
    bool m_busy;
};

#endif // IWSCAN_H
