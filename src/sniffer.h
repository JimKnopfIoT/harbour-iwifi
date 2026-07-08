/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Reads the monitor-mode sniffer's JSON snapshot (written by the iwsniff root
  helper) and exposes it to QML. `available` is true only while a fresh snapshot
  exists — i.e. the external adapter + monitor capture are actually running.

  PRIVACY: the snapshot contains only per-AP data (incl. an associated-client
  COUNT and defensive attack indicators) — no client MAC addresses, no probe
  lists, no per-device profiling. This class therefore exposes only AP records
  and a per-BSSID client count; there is no list of individual clients.
*/
#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <QVariantList>
#include <QVariantMap>
#include <QString>
#include <QHash>

class QTimer;

class Sniffer : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool available READ available NOTIFY changed)
    Q_PROPERTY(QVariantList aps READ aps NOTIFY changed)
public:
    explicit Sniffer(QObject *parent = nullptr);

    bool available() const { return m_available; }
    QVariantList aps() const { return m_aps; }

    Q_INVOKABLE QVariantMap apForBssid(const QString &bssid) const;
    Q_INVOKABLE int clientCount(const QString &bssid) const;   // associated, O(1)

signals:
    void changed();

private slots:
    void poll();

private:
    QString m_path;
    qint64 m_mtime;
    bool m_available;
    QVariantList m_aps;
    QHash<QString, int> m_count;                  // bssid -> associated client count
    QTimer *m_timer;
};

#endif // SNIFFER_H
