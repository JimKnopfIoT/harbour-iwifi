/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "cvelookup.h"

#include <QUrl>
#include <QUrlQuery>
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

CveLookup::CveLookup(QObject *parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
    , m_current(0)
    , m_busy(false)
{
    connect(m_nam, &QNetworkAccessManager::finished, this, &CveLookup::onFinished);
    fetchKev();
}

void CveLookup::fetchKev()
{
    QNetworkRequest req(QUrl("https://www.cisa.gov/sites/default/files/"
                             "feeds/known_exploited_vulnerabilities.json"));
    req.setHeader(QNetworkRequest::UserAgentHeader, "harbour-iwifi");
    m_nam->get(req);
}

void CveLookup::search(const QString &terms)
{
    // supersede any running search so the previous query's result can't land
    // in the new router's view
    if (m_current) {
        m_current->abort();
        m_current = 0;
    }
    m_results.clear();
    const QString t = terms.trimmed();
    if (t.isEmpty()) {
        m_busy = false;
        m_status = tr("No model to search for");
        emit changed();
        return;
    }
    QUrl url("https://services.nvd.nist.gov/rest/json/cves/2.0");
    QUrlQuery q;
    q.addQueryItem("keywordSearch", t);
    q.addQueryItem("resultsPerPage", "30");
    url.setQuery(q);

    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "harbour-iwifi");
    m_busy = true;
    m_status = tr("Searching NVD for \"%1\"…").arg(t);
    emit changed();
    m_current = m_nam->get(req);
}

void CveLookup::onFinished(QNetworkReply *reply)
{
    reply->deleteLater();
    const bool isKev = reply->url().toString().contains("known_exploited");

    if (isKev) {
        if (reply->error() == QNetworkReply::NoError) {
            const QJsonArray vulns = QJsonDocument::fromJson(reply->readAll())
                    .object().value("vulnerabilities").toArray();
            for (const QJsonValue &v : vulns)
                m_kev.insert(v.toObject().value("cveID").toString());
            // re-flag results that were already shown before KEV finished
            bool changedAny = false;
            for (int i = 0; i < m_results.size(); ++i) {
                QVariantMap m = m_results[i].toMap();
                const bool k = m_kev.contains(m.value("id").toString());
                if (m.value("kev").toBool() != k) {
                    m.insert("kev", k);
                    m_results[i] = m;
                    changedAny = true;
                }
            }
            if (changedAny)
                emit changed();
        }
        return;
    }

    // CVE search reply: discard anything that isn't the latest request, so a
    // slow or aborted previous search can never overwrite the current view.
    if (reply != m_current)
        return;
    m_current = 0;
    m_busy = false;

    if (reply->error() != QNetworkReply::NoError) {
        m_status = tr("Network error: %1").arg(reply->errorString());
        emit changed();
        return;
    }

    const QByteArray data = reply->readAll();
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isObject()) {
        m_status = tr("Unexpected response from NVD");
        emit changed();
        return;
    }
    const QJsonObject root = doc.object();
    const QJsonArray vulns = root.value("vulnerabilities").toArray();

    QVariantList list;
    for (const QJsonValue &v : vulns) {
        const QJsonObject cve = v.toObject().value("cve").toObject();
        const QString id = cve.value("id").toString();

        QString summary;
        const QJsonArray descs = cve.value("descriptions").toArray();
        for (const QJsonValue &d : descs) {
            const QJsonObject o = d.toObject();
            if (o.value("lang").toString() == "en") {
                summary = o.value("value").toString();
                break;
            }
        }

        QString severity;
        double score = -1.0;
        const QJsonObject metrics = cve.value("metrics").toObject();
        const char *keys[] = { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" };
        for (int k = 0; k < 3 && severity.isEmpty(); ++k) {
            const QJsonArray arr = metrics.value(keys[k]).toArray();
            if (arr.isEmpty())
                continue;
            const QJsonObject cvss = arr.first().toObject();
            const QJsonObject cd = cvss.value("cvssData").toObject();
            score = cd.value("baseScore").toDouble(-1.0);
            severity = cd.value("baseSeverity").toString();
            if (severity.isEmpty())
                severity = cvss.value("baseSeverity").toString();
        }

        QVariantMap m;
        m.insert("id", id);
        m.insert("severity", severity.isEmpty() ? QStringLiteral("?") : severity);
        m.insert("score", score);
        m.insert("summary", summary);
        m.insert("url", QStringLiteral("https://nvd.nist.gov/vuln/detail/") + id);
        m.insert("kev", m_kev.contains(id));
        m.insert("exploitdb", QStringLiteral("https://www.exploit-db.com/search?cve=") + id);
        list.append(m);
    }

    m_results = list;
    const int total = root.value("totalResults").toInt(list.size());
    m_status = list.isEmpty()
            ? tr("No CVEs found")
            : tr("%1 CVE(s) — showing %2").arg(total).arg(list.size());
    emit changed();
}
