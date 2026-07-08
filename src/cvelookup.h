/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Looks up CVEs for a router model via the NIST NVD API 2.0 (free, no key;
  5 req / 30 s). Needs Internet. Query is a free-text keyword built from the
  vendor + model/SSID; the user can edit it.
*/
#ifndef CVELOOKUP_H
#define CVELOOKUP_H

#include <QObject>
#include <QVariantList>
#include <QString>
#include <QSet>
#include <QNetworkAccessManager>
#include <QNetworkReply>

class CveLookup : public QObject
{
    Q_OBJECT
    Q_PROPERTY(QVariantList results READ results NOTIFY changed)
    Q_PROPERTY(QString status READ status NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
public:
    explicit CveLookup(QObject *parent = nullptr);

    QVariantList results() const { return m_results; }
    QString status() const { return m_status; }
    bool busy() const { return m_busy; }

    Q_INVOKABLE void search(const QString &terms);

signals:
    void changed();

private slots:
    void onFinished(QNetworkReply *reply);

private:
    void fetchKev();

    QNetworkAccessManager *m_nam;
    QNetworkReply *m_current;   // in-flight CVE search (for cancel/supersede)
    QVariantList m_results;
    QString m_status;
    bool m_busy;
    QSet<QString> m_kev;   // CVE IDs in the CISA Known-Exploited catalog
};

#endif // CVELOOKUP_H
