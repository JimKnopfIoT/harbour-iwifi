/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.

  Minimal string key/value store over QSettings, exposed to QML.
*/
#ifndef SETTINGSWRAPPER_H
#define SETTINGSWRAPPER_H

#include <QObject>
#include <QSettings>
#include <QString>

class SettingsWrapper : public QObject
{
    Q_OBJECT
public:
    explicit SettingsWrapper(QObject *parent = nullptr);

    Q_INVOKABLE QString value(const QString &key) const;
    Q_INVOKABLE void setValue(const QString &key, const QString &value);

private:
    QSettings m_settings;
};

#endif // SETTINGSWRAPPER_H
