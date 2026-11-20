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
