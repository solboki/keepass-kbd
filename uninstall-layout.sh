#!/bin/sh
# Retire la disposition clavier KeePass et sa page Paramètres (devel-su sh uninstall-layout.sh)
set -e
DEST=/usr/share/maliit/plugins/com/jolla/layouts
if [ "$(id -u)" != 0 ]; then echo "À lancer avec : devel-su sh $0"; exit 1; fi
rm -f "$DEST/keepass.qml" "$DEST/KpxButton.qml" "$DEST/KpxMiniKeyboard.qml" "$DEST/KpxBackspaceButton.qml" "$DEST/KpxLineField.qml" \
      "$DEST/layouts_keepass.conf"
rm -f /usr/share/maliit/plugins/com/jolla/handlers/KeepassInputHandler.qml
rm -rf /usr/share/jolla-settings/pages/keepass-kbd
rm -f /usr/share/jolla-settings/entries/keepass-kbd.json
rm -rf /usr/share/keepass-kbd
rm -f /usr/share/icons/hicolor/86x86/apps/keepass-kbd.png
echo "Disposition et page Paramètres retirées"
