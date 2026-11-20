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

if [ "$1" = 0 ]; then
    # Désinstallation complète : retirer la disposition et arrêter le service.
    for_each_session 'cur=$(dconf read /sailfish/text_input/enabled_layouts); new=$(echo "$cur" | sed "s/, *'"'"'keepass.qml'"'"'//; s/'"'"'keepass.qml'"'"', *//"); dconf write /sailfish/text_input/enabled_layouts "$new"; [ "$(dconf read /sailfish/text_input/active_layout)" = "'"'"'keepass.qml'"'"'" ] && dconf write /sailfish/text_input/active_layout "$(echo "$new" | sed "s/^\\[ *\\('"'"'[^'"'"']*'"'"'\\).*/\\1/")"; systemctl --user stop keepass-kbd.service'
    for_each_session 'systemctl --user daemon-reload; systemctl --user stop keepass-kbd.service'
# Secours (pkill de BusyBox : -x ne reconnaît pas ce processus, -f oui).
pkill -f '^/usr/bin/keepass-kbd daemon' 2>/dev/null || :
fi
