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
install -m 644 "$SRC/qml/KpxButton.qml" "$SRC/qml/KpxMiniKeyboard.qml" "$SRC/qml/KpxBackspaceButton.qml" "$DEST/"
install -m 644 "$SRC/dist/layouts_keepass.conf" "$DEST/"
install -m 644 "$SRC/qml/handlers/KeepassInputHandler.qml" /usr/share/maliit/plugins/com/jolla/handlers/
mkdir -p "$PAGES"
stamp "$SRC/settings/main.qml" "$PAGES/main.qml"
install -m 644 "$SRC/settings/KeepassTextInputSettings.qml" "$PAGES/"
install -D -m 644 "$SRC/settings/keepass-kbd.json" /usr/share/jolla-settings/entries/keepass-kbd.json
echo "Clavier KeePass $VERSION installé (disposition + Paramètres › Saisie de texte)"
