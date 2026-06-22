/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Discovers clients on the CONNECTED network. Reads the kernel ARP cache
  (/proc/net/arp) and, on request, does a quick TCP-connect sweep of the /24 to
  provoke ARP resolution for hosts not yet in the cache. Works because the app
  shares the host network namespace (the Internet permission drops `net none`).
  Foreign APs' clients are NOT obtainable this way — only the joined network.
*/
#ifndef LANSCAN_H
#define LANSCAN_H

#include <QObject>
#include <QVariantList>
#include <QString>
#include <QList>
#include <QTcpSocket>
#include <QTimer>

class LanScan : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList hosts READ hosts NOTIFY changed)
    Q_PROPERTY(int count READ count NOTIFY changed)
    Q_PROPERTY(QString subnet READ subnet NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
public:
    explicit LanScan(QObject *parent = nullptr);

    QVariantList hosts() const { return m_hosts; }
    int count() const { return m_hosts.size(); }
    QString subnet() const { return m_subnet; }
    bool busy() const { return m_busy; }

    Q_INVOKABLE void refresh();   // read ARP cache now
    Q_INVOKABLE void sweep();     // active TCP sweep of the /24, then re-read

signals:
    void changed();

private slots:
    void onSweepDone();

private:
    void readArp();
    QString ownIp() const;        // our IPv4 on the LAN

    QVariantList m_hosts;
    QString m_subnet;
    QString m_ownIp;
    bool m_busy;
    QList<QTcpSocket *> m_sockets;
    QTimer *m_sweepTimer;
};

#endif // LANSCAN_H
