/*
  Copyright (C) 2015 Petr Vytovtov
  Contact: Petr Vytovtov <iwifi@protonmail.ch>
  All rights reserved.

  This file is part of WiFi Analyzer for Sailfish OS.

  WiFi Analyzer is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  WiFi Analyzer is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with WiFi Analyzer.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef QT_QML_DEBUG
#include <QtQuick>
#endif

#include <QGuiApplication>
#include <QQmlContext>
#include <QQuickView>
#include <QScopedPointer>

#include <sailfishapp.h>

#include "settingswrapper.h"
#include "iwbackend.h"
#include "sensorreader.h"
#include "wpascan.h"
#include "cvelookup.h"
#include "lanscan.h"
#include "routerinfo.h"
#include "sniffer.h"
#include "battery.h"
#include "osmfetch.h"
#include "monitorctl.h"


int main(int argc, char *argv[])
{
    QScopedPointer<QGuiApplication> application(SailfishApp::application(argc, argv));
    QScopedPointer<QQuickView> view(SailfishApp::createView());

    QScopedPointer<SettingsWrapper> settings(new SettingsWrapper(view.data()));
    view->rootContext()->setContextProperty("settings", settings.data());

    QScopedPointer<IwBackend> iw(new IwBackend(view.data()));
    view->rootContext()->setContextProperty("iw", iw.data());

    QScopedPointer<SensorReader> sensor(new SensorReader(view.data()));
    view->rootContext()->setContextProperty("sensor", sensor.data());

    QScopedPointer<WpaScan> iwscan(new WpaScan(view.data()));
    view->rootContext()->setContextProperty("iwscan", iwscan.data());

    QScopedPointer<CveLookup> cve(new CveLookup(view.data()));
    view->rootContext()->setContextProperty("cve", cve.data());

    QScopedPointer<LanScan> lan(new LanScan(view.data()));
    view->rootContext()->setContextProperty("lan", lan.data());

    QScopedPointer<RouterInfo> router(new RouterInfo(view.data()));
    view->rootContext()->setContextProperty("router", router.data());

    QScopedPointer<Sniffer> sniffer(new Sniffer(view.data()));
    view->rootContext()->setContextProperty("sniffer", sniffer.data());

    QScopedPointer<Battery> battery(new Battery(view.data()));
    view->rootContext()->setContextProperty("battery", battery.data());

    QScopedPointer<OsmFetch> osm(new OsmFetch(view.data()));
    view->rootContext()->setContextProperty("osm", osm.data());

    QScopedPointer<MonitorControl> monitor(new MonitorControl(view.data()));
    view->rootContext()->setContextProperty("monitor", monitor.data());

    view->setSource(SailfishApp::pathTo("qml/harbour-iwifi.qml"));
    view->show();

    return application->exec();
}
