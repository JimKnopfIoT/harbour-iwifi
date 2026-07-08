/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "lanscan.h"

#include <QFile>
#include <QTextStream>
#include <QStringList>
#include <QNetworkInterface>
#include <QHostAddress>

LanScan::LanScan(QObject *parent)
    : QObject(parent)
    , m_busy(false)
    , m_sweepTimer(new QTimer(this))
{
    m_sweepTimer->setSingleShot(true);
    m_sweepTimer->setInterval(2500);
    connect(m_sweepTimer, &QTimer::timeout, this, &LanScan::onSweepDone);
}

QString LanScan::ownIp() const
{
    foreach (const QNetworkInterface &iface, QNetworkInterface::allInterfaces()) {
        if (iface.flags().testFlag(QNetworkInterface::IsLoopBack)
                || !iface.flags().testFlag(QNetworkInterface::IsUp))
            continue;
        foreach (const QNetworkAddressEntry &e, iface.addressEntries()) {
            const QHostAddress a = e.ip();
            if (a.protocol() == QAbstractSocket::IPv4Protocol
                    && !a.isLoopback()
                    && a.toString().startsWith("192.168."))
                return a.toString();
        }
    }
    // fallback: any non-loopback IPv4
    foreach (const QHostAddress &a, QNetworkInterface::allAddresses())
        if (a.protocol() == QAbstractSocket::IPv4Protocol && !a.isLoopback())
            return a.toString();
    return QString();
}

static QString defaultGateway()
{
    // /proc/net/route: default route has Destination 00000000; Gateway is a
    // little-endian hex IPv4.
    QFile f("/proc/net/route");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();
    QTextStream ts(&f);
    ts.readLine(); // header
    QString line;
    while (!(line = ts.readLine()).isNull()) {
        const QStringList c = line.split('\t', QString::SkipEmptyParts);
        if (c.size() < 3)
            continue;
        if (c.at(1) == "00000000") {
            bool ok = false;
            const quint32 g = c.at(2).toUInt(&ok, 16);
            if (ok && g != 0)
                return QString("%1.%2.%3.%4")
                        .arg(g & 0xff).arg((g >> 8) & 0xff)
                        .arg((g >> 16) & 0xff).arg((g >> 24) & 0xff);
        }
    }
    return QString();
}

void LanScan::readArp()
{
    m_ownIp = ownIp();
    const QString gw = defaultGateway();

    int dot = m_ownIp.lastIndexOf('.');
    m_subnet = dot > 0 ? (m_ownIp.left(dot) + ".0/24") : QString();

    QVariantList list;

    // our own device first
    if (!m_ownIp.isEmpty()) {
        QVariantMap me;
        me.insert("ip", m_ownIp);
        me.insert("mac", QString());
        me.insert("self", true);
        me.insert("gateway", false);
        list.append(me);
    }

    QFile f("/proc/net/arp");
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream ts(&f);
        ts.readLine(); // header
        QString line;
        while (!(line = ts.readLine()).isNull()) {
            const QStringList c = line.split(' ', QString::SkipEmptyParts);
            if (c.size() < 6)
                continue;
            const QString ip = c.at(0);
            const QString flags = c.at(2);
            const QString mac = c.at(3);
            if (flags == "0x0" || mac == "00:00:00:00:00:00")
                continue;            // incomplete entry
            if (ip == m_ownIp)
                continue;
            QVariantMap h;
            h.insert("ip", ip);
            h.insert("mac", mac.toUpper());
            h.insert("self", false);
            h.insert("gateway", ip == gw);
            list.append(h);
        }
    }

    m_hosts = list;
    emit changed();
}

void LanScan::refresh()
{
    readArp();
}

void LanScan::sweep()
{
    if (m_busy)
        return;
    const QString ip = ownIp();
    const int dot = ip.lastIndexOf('.');
    if (dot < 0) {
        readArp();
        return;
    }
    const QString base = ip.left(dot + 1);   // e.g. "192.168.1."
    const int self = ip.mid(dot + 1).toInt();

    m_busy = true;
    emit changed();

    // Fire a quick TCP connect at every host in the /24. We don't care whether
    // the port is open — the SYN forces ARP resolution, so the kernel learns
    // the host's MAC even when the connection is refused.
    for (int i = 1; i <= 254; ++i) {
        if (i == self)
            continue;
        QTcpSocket *s = new QTcpSocket(this);
        m_sockets.append(s);
        s->connectToHost(base + QString::number(i), 80);
    }
    m_sweepTimer->start();
}

void LanScan::onSweepDone()
{
    foreach (QTcpSocket *s, m_sockets) {
        s->abort();
        s->deleteLater();
    }
    m_sockets.clear();
    m_busy = false;
    readArp();
}
