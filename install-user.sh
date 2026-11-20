#!/bin/sh
# Installe le service utilisateur (sans root) et active la disposition KeePass.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
install -D -m 755 "$SRC/target/release/keepass-kbd" "$HOME/.local/bin/keepass-kbd"
install -D -m 644 "$SRC/dist/keepass-kbd.service" "$HOME/.config/systemd/user/keepass-kbd.service"
"$HOME/.local/bin/keepass-kbd" generate 4 l >/dev/null   # simple test d'exécution
systemctl --user daemon-reload
systemctl --user enable keepass-kbd.service
systemctl --user restart keepass-kbd.service
if [ -f /usr/share/maliit/plugins/com/jolla/layouts/keepass.qml ]; then
    CUR=$(dconf read /sailfish/text_input/enabled_layouts)
    case "$CUR" in
        *keepass.qml*) ;;
        "[]"|"") dconf write /sailfish/text_input/enabled_layouts "['futo.qml', 'keepass.qml']" ;;
        *) dconf write /sailfish/text_input/enabled_layouts "$(echo "$CUR" | sed "s/]\$/, 'keepass.qml']/")" ;;
    esac
    systemctl --user restart maliit-server.service
    echo "Disposition KeePass activée."
else
    echo "Disposition non installée : lancez d'abord  devel-su sh $SRC/install-layout.sh"
fi
