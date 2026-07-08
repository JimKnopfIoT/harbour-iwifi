/*
  harbour-iwifi — WiFi security checker for Sailfish OS
  Copyright (C) 2026  JimKnopfIoT — GPLv3 or later.
*/
#include "settingswrapper.h"

#include <QStandardPaths>

SettingsWrapper::SettingsWrapper(QObject *parent)
    : QObject(parent)
    , m_settings(QStandardPaths::writableLocation(QStandardPaths::ConfigLocation)
                 + QStringLiteral("/org.iwifi/iwifi/harbour-iwifi.conf"),
                 QSettings::NativeFormat)
{
}

QString SettingsWrapper::value(const QString &key) const
{
    return m_settings.value(key).toString();
}

void SettingsWrapper::setValue(const QString &key, const QString &value)
{
    m_settings.setValue(key, value);
}
