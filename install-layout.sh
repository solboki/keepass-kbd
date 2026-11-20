#!/bin/sh
# Installe la disposition clavier KeePass et ses pages Paramètres (root : devel-su sh install-layout.sh)
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST=/usr/share/maliit/plugins/com/jolla/layouts
PAGES=/usr/share/jolla-settings/pages/keepass-kbd
if [ "$(id -u)" != 0 ]; then echo "À lancer avec : devel-su sh $0"; exit 1; fi
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$SRC/Cargo.toml" | head -n 1)
stamp() { sed "s/@VERSION@/$VERSION/g" "$1" > "$2" && chmod 644 "$2"; }
stamp "$SRC/qml/keepass.qml" "$DEST/keepass.qml"
install -m 644 "$SRC/qml/KpxButton.qml" "$SRC/qml/KpxMiniKeyboard.qml" "$SRC/qml/KpxBackspaceButton.qml" "$SRC/qml/KpxLineField.qml" "$SRC/qml/KpxStrings.js" "$SRC/qml/KpxNumpadKey.qml" "$DEST/"
install -m 644 "$SRC/dist/layouts_keepass.conf" "$DEST/"
install -m 644 "$SRC/qml/handlers/KeepassInputHandler.qml" /usr/share/maliit/plugins/com/jolla/handlers/
mkdir -p "$PAGES"
stamp "$SRC/settings/main.qml" "$PAGES/main.qml"
install -m 644 "$SRC/settings/KeepassTextInputSettings.qml" "$SRC/qml/KpxStrings.js" "$PAGES/"
install -m 644 "$SRC"/translations/settings-keepass-kbd*.qm /usr/share/translations/
install -D -m 644 "$SRC/settings/keepass-kbd.json" /usr/share/jolla-settings/entries/keepass-kbd.json
install -D -m 644 "$SRC/assets/keepass-kbd-256.png" /usr/share/keepass-kbd/keepass-kbd.png
# Désinstallation depuis les Paramètres : scripts + règle polkit limitée à l'utilisateur propriétaire.
OWNER=$(stat -c %U "$SRC")
install -D -m 755 "$SRC/dist/uninstall/uninstall" /usr/libexec/keepass-kbd/uninstall
install -D -m 755 "$SRC/dist/uninstall/uninstall-system" /usr/libexec/keepass-kbd/uninstall-system
install -D -m 644 "$SRC/dist/polkit/org.keepasskbd.policy" /usr/share/polkit-1/actions/org.keepasskbd.policy
sed "s/@USER@/$OWNER/" "$SRC/dist/polkit/49-keepass-kbd.rules" > /usr/share/polkit-1/rules.d/49-keepass-kbd.rules
chmod 644 /usr/share/polkit-1/rules.d/49-keepass-kbd.rules
install -D -m 644 "$SRC/assets/keepass-kbd-86.png" /usr/share/icons/hicolor/86x86/apps/keepass-kbd.png
# Touche KeePass dans le pavé numérique du clavier Jolla, remise à chaque démarrage.
install -D -m 755 "$SRC/dist/numpad/numpad-patch" /usr/libexec/keepass-kbd/numpad-patch
install -D -m 644 "$SRC/dist/numpad/keepass-kbd-numpad.service" /usr/lib/systemd/system/keepass-kbd-numpad.service
systemctl daemon-reload; systemctl enable keepass-kbd-numpad.service
/usr/libexec/keepass-kbd/numpad-patch apply || :
echo "Clavier KeePass $VERSION installé (disposition + Paramètres › Entrée de texte)"
