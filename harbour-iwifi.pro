# NOTICE:
#
# Application name defined in TARGET has a corresponding QML filename.
# If name defined in TARGET is changed, the following needs to be done
# to match new name:
#   - corresponding QML filename must be changed
#   - desktop icon filename must be changed
#   - desktop filename must be changed
#   - icon definition filename in desktop file must be changed
#   - translation filenames have to be changed

# The name of your application
TARGET = harbour-iwifi

CONFIG += sailfishapp

QT += sensors dbus network

HEADERS += \
    src/settingswrapper.h \
    src/iwbackend.h \
    src/sensorreader.h \
    src/wpascan.h \
    src/cvelookup.h \
    src/lanscan.h \
    src/routerinfo.h \
    src/sniffer.h \
    src/battery.h \
    src/osmfetch.h \
    src/monitorctl.h

SOURCES += \
    src/harbour-iwifi.cpp \
    src/settingswrapper.cpp \
    src/iwbackend.cpp \
    src/sensorreader.cpp \
    src/wpascan.cpp \
    src/cvelookup.cpp \
    src/lanscan.cpp \
    src/routerinfo.cpp \
    src/sniffer.cpp \
    src/battery.cpp \
    src/osmfetch.cpp \
    src/monitorctl.cpp

# Bundled MAC-vendor (OUI) database, derived from Wireshark 'manuf' (GPLv2)
oui.files = data/oui.tsv
oui.path = /usr/share/$${TARGET}
INSTALLS += oui

# Sailjail permission: allow talking to wpa_supplicant over D-Bus
sjperm.files = data/WpaScan.permission
sjperm.path = /etc/sailjail/permissions
INSTALLS += sjperm

# D-Bus system policy: allow the app's user to read wpa_supplicant
dbuspolicy.files = data/harbour-iwifi-wpa.conf
dbuspolicy.path = /etc/dbus-1/system.d
INSTALLS += dbuspolicy

OTHER_FILES += qml/harbour-iwifi.qml \
    qml/cover/CoverPage.qml \
    rpm/harbour-iwifi.changes.in \
    rpm/harbour-iwifi.spec \
    rpm/harbour-iwifi.yaml \
    translations/*.ts \
    harbour-iwifi.desktop \
    qml/pages/AboutPage.qml \
    qml/pages/ListPage.qml

SAILFISHAPP_ICONS = 86x86 108x108 128x128 172x172 256x256

# to disable building translations every time, comment out the
# following CONFIG line
CONFIG += sailfishapp_i18n

# German translation is enabled as an example. If you aren't
# planning to localize your app, remember to comment out the
# following TRANSLATIONS line. And also do not forget to
# modify the localized app name in the the .desktop file.
TRANSLATIONS += translations/harbour-iwifi-ru.ts \
    translations/harbour-iwifi-sv.ts \
    translations/harbour-iwifi-cs.ts \
    translations/harbour-iwifi-fr.ts \
    translations/harbour-iwifi-fi.ts \
    translations/harbour-iwifi-pl.ts \
    translations/harbour-iwifi-zh_CN.ts

DISTFILES += \
    qml/views/TopMenu.qml
