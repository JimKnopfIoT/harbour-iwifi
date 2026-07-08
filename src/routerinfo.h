/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Queries the connected router over TR-064 (AVM FRITZ!Box; port 49000):
    - tr64desc.xml (no auth) -> exact model / manufacturer / friendly name
    - X_AVM-DE_GetHostListPath (digest auth) -> full host list with InterfaceType
      so we can show ONLY the real Wi-Fi (802.11) clients, not wired hosts.
  ARP/L3 can't tell wired from wireless — only the router knows. Needs the
  FRITZ!Box password. Works because the app shares the host network namespace.
*/
#ifndef ROUTERINFO_H
#define ROUTERINFO_H

#include <QObject>
#include <QVariantList>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class RouterInfo : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QString model READ model NOTIFY infoChanged)
    Q_PROPERTY(QString manufacturer READ manufacturer NOTIFY infoChanged)
    Q_PROPERTY(QString friendlyName READ friendlyName NOTIFY infoChanged)
    Q_PROPERTY(QString gateway READ gateway NOTIFY infoChanged)
    Q_PROPERTY(bool tr064 READ tr064 NOTIFY infoChanged)         // FRITZ!Box reachable
    Q_PROPERTY(QVariantList wifiClients READ wifiClients NOTIFY clientsChanged)
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY statusChanged)
public:
    explicit RouterInfo(QObject *parent = nullptr);

    QString model() const { return m_model; }
    QString manufacturer() const { return m_manufacturer; }
    QString friendlyName() const { return m_friendly; }
    QString gateway() const { return m_gateway; }
    bool tr064() const { return m_tr064; }
    QVariantList wifiClients() const { return m_wifiClients; }
    QString status() const { return m_status; }
    bool busy() const { return m_busy; }

    Q_INVOKABLE void probe();                                    // model (no auth)
    Q_INVOKABLE void loadWifiClients(const QString &user, const QString &password);

signals:
    void infoChanged();
    void clientsChanged();
    void statusChanged();

private slots:
    void onAuth(QNetworkReply *reply, QAuthenticator *auth);

private:
    QString gatewayIp() const;
    QString base() const { return "http://" + m_gateway + ":49000"; }
    void getHostList(const QString &path);
    void setStatus(const QString &s, bool busy);

    QNetworkAccessManager *m_nam;
    QString m_model, m_manufacturer, m_friendly, m_gateway, m_status;
    QString m_user, m_pass;
    bool m_tr064;
    bool m_busy;
    QVariantList m_wifiClients;
};

#endif // ROUTERINFO_H
