# Third-party notices

## Upstream application
harbour-iwifi is derived from **WiFi Analyzer for Sailfish OS** by Petr Vytovtov
(osanwe), licensed under the **GNU General Public License v3**.
Source: <https://github.com/osanwe/harbour-wifianalyzer> (and the maintained fork
<https://github.com/a-dekker/harbour-wifianalyser>).

## MAC vendor database (`data/oui.tsv`)
Derived from the **Wireshark `manuf`** database, which is distributed under the
**GNU General Public License v2 or later**. The file shipped here is a compacted
form (MAC prefix, prefix length in nibbles, short vendor name) generated from the
upstream `manuf` list. Wireshark: <https://www.wireshark.org/>.

The `manuf` data itself derives from the IEEE MA-L/MA-M/MA-S registries plus
manual additions maintained by the Wireshark project.

## Icons
WiFi glyphs are drawn at runtime by the app (`qml/views/WifiIcon.qml`); no
third-party icon assets are bundled for the hotspot/client badges.
