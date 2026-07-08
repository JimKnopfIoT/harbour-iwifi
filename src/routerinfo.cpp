/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "routerinfo.h"

#include <QFile>
#include <QTextStream>
#include <QStringList>
#include <QUrl>
#include <QNetworkRequest>
#include <QAuthenticator>
#include <QXmlStreamReader>

RouterInfo::RouterInfo(QObject *parent)
    : QObject(parent)
    , m_nam(new QNetworkAccessManager(this))
    , m_tr064(false)
    , m_busy(false)
{
    connect(m_nam, &QNetworkAccessManager::authenticationRequired,
            this, &RouterInfo::onAuth);
}

QString RouterInfo::gatewayIp() const
{
    QFile f("/proc/net/route");
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return QString();
    QTextStream ts(&f);
    ts.readLine(); // header
    QString line;
    while (!(line = ts.readLine()).isNull()) {
        const QStringList c = line.split('\t', QString::SkipEmptyParts);
        if (c.size() < 3 || c.at(1) != "00000000")
            continue;
        bool ok = false;
        const quint32 g = c.at(2).toUInt(&ok, 16);
        if (ok && g != 0)
            return QString("%1.%2.%3.%4")
                    .arg(g & 0xff).arg((g >> 8) & 0xff)
                    .arg((g >> 16) & 0xff).arg((g >> 24) & 0xff);
    }
    return QString();
}

void RouterInfo::setStatus(const QString &s, bool busy)
{
    m_status = s;
    m_busy = busy;
    emit statusChanged();
}

void RouterInfo::onAuth(QNetworkReply *reply, QAuthenticator *auth)
{
    // provide credentials exactly once per reply, else a wrong password loops
    if (reply->property("authTried").toBool())
        return;
    reply->setProperty("authTried", true);
    auth->setUser(m_user);
    auth->setPassword(m_pass);
}

void RouterInfo::probe()
{
    m_gateway = gatewayIp();
    emit infoChanged();
    if (m_gateway.isEmpty()) {
        setStatus(tr("Not connected to a network"), false);
        return;
    }
    setStatus(tr("Querying router…"), true);

    QNetworkRequest req(QUrl(base() + "/tr64desc.xml"));
    req.setHeader(QNetworkRequest::UserAgentHeader, "harbour-iwifi");
    QNetworkReply *r = m_nam->get(req);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        r->deleteLater();
        if (r->error() != QNetworkReply::NoError) {
            m_tr064 = false;
            emit infoChanged();
            setStatus(tr("No TR-064/FRITZ!Box at %1").arg(m_gateway), false);
            return;
        }
        QXmlStreamReader xml(r->readAll());
        QString fn, man, mod, modnum;
        while (!xml.atEnd()) {
            if (xml.readNext() != QXmlStreamReader::StartElement)
                continue;
            const QString n = xml.name().toString();
            if (n == "friendlyName" && fn.isEmpty()) fn = xml.readElementText();
            else if (n == "manufacturer" && man.isEmpty()) man = xml.readElementText();
            else if (n == "modelName" && mod.isEmpty()) mod = xml.readElementText();
            else if (n == "modelNumber" && modnum.isEmpty()) modnum = xml.readElementText();
        }
        m_friendly = fn;
        m_manufacturer = man;
        m_model = mod + (modnum.isEmpty() ? QString() : " " + modnum);
        m_tr064 = true;
        emit infoChanged();
        setStatus(m_model.isEmpty() ? fn : m_model, false);
    });
}

void RouterInfo::loadWifiClients(const QString &user, const QString &password)
{
    m_user = user;
    m_pass = password;
    if (m_gateway.isEmpty())
        m_gateway = gatewayIp();
    if (m_gateway.isEmpty()) {
        setStatus(tr("Not connected to a network"), false);
        return;
    }
    m_wifiClients.clear();
    emit clientsChanged();
    setStatus(tr("Loading Wi-Fi clients…"), true);

    const QByteArray soap =
            "<?xml version=\"1.0\"?>"
            "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
            "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
            "<s:Body><u:X_AVM-DE_GetHostListPath "
            "xmlns:u=\"urn:dslforum-org:service:Hosts:1\"/>"
            "</s:Body></s:Envelope>";

    QNetworkRequest req(QUrl(base() + "/upnp/control/hosts"));
    req.setHeader(QNetworkRequest::ContentTypeHeader,
                  "text/xml; charset=\"utf-8\"");
    req.setRawHeader("SOAPAction",
                     "urn:dslforum-org:service:Hosts:1#X_AVM-DE_GetHostListPath");
    QNetworkReply *r = m_nam->post(req, soap);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        r->deleteLater();
        if (r->error() != QNetworkReply::NoError) {
            setStatus(tr("Router login failed or TR-064 off (%1)")
                      .arg(r->errorString()), false);
            return;
        }
        QXmlStreamReader xml(r->readAll());
        QString path;
        while (!xml.atEnd()) {
            if (xml.readNext() == QXmlStreamReader::StartElement
                    && xml.name() == "NewX_AVM-DE_HostListPath") {
                path = xml.readElementText();
                break;
            }
        }
        if (path.isEmpty()) {
            setStatus(tr("Unexpected TR-064 response"), false);
            return;
        }
        getHostList(path);
    });
}

void RouterInfo::getHostList(const QString &path)
{
    QNetworkRequest req(QUrl(base() + path));
    QNetworkReply *r = m_nam->get(req);
    connect(r, &QNetworkReply::finished, this, [this, r]() {
        r->deleteLater();
        if (r->error() != QNetworkReply::NoError) {
            setStatus(tr("Host list error: %1").arg(r->errorString()), false);
            return;
        }
        QXmlStreamReader xml(r->readAll());
        QVariantList list;
        QVariantMap cur;
        QString field;
        bool inItem = false;
        while (!xml.atEnd()) {
            const QXmlStreamReader::TokenType t = xml.readNext();
            if (t == QXmlStreamReader::StartElement) {
                const QString n = xml.name().toString();
                if (n == "Item") { cur.clear(); inItem = true; field.clear(); }
                else if (inItem) field = n;
            } else if (t == QXmlStreamReader::Characters && inItem
                       && !field.isEmpty() && !xml.isWhitespace()) {
                cur.insert(field, xml.text().toString());
            } else if (t == QXmlStreamReader::EndElement) {
                if (xml.name() == "Item") {
                    inItem = false;
                    if (cur.value("InterfaceType").toString() == "802.11") {
                        QVariantMap h;
                        h.insert("ip", cur.value("IPAddress"));
                        h.insert("mac", cur.value("MACAddress").toString().toUpper());
                        h.insert("name", cur.value("HostName"));
                        h.insert("active", cur.value("Active").toString() == "1");
                        h.insert("speed", cur.value("X_AVM-DE_Speed"));
                        list.append(h);
                    }
                } else {
                    field.clear();
                }
            }
        }
        m_wifiClients = list;
        emit clientsChanged();
        setStatus(tr("%1 Wi-Fi client(s)").arg(list.size()), false);
    });
}
