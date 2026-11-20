# for_each_session "commande" : exécute une commande dans chaque session utilisateur active.
for_each_session() {
    for d in /run/user/[0-9]*; do
        [ -S "$d/dbus/user_bus_socket" ] || continue
        uid=${d##*/}
        user=$(getent passwd "$uid" | cut -d: -f1)
        [ -n "$user" ] || continue
        su -s /bin/sh "$user" -c "export XDG_RUNTIME_DIR=$d DBUS_SESSION_BUS_ADDRESS=unix:path=$d/dbus/user_bus_socket; $1" >/dev/null 2>&1 || :
    done
}

# Nouvelle version du service : il redémarre à la demande (activation D-Bus).
pkill -x keepass-kbd 2>/dev/null || :
if [ "$1" = 1 ]; then
    # Première installation : activer la disposition KeePass à côté des claviers existants.
    for_each_session 'cur=$(dconf read /sailfish/text_input/enabled_layouts); case "$cur" in *keepass.qml*) ;; ""|"[]") ;; *) dconf write /sailfish/text_input/enabled_layouts "$(echo "$cur" | sed "s/]\$/, '"'"'keepass.qml'"'"']/")" ;; esac'
fi
# Recharger le clavier pour prendre en compte les fichiers QML.
for_each_session 'systemctl --user restart maliit-server.service'
