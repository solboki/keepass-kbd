# keepass-kbd

Disposition clavier « KeePass » pour Sailfish OS (Maliit, à côté de FUTO) et service
utilisateur qui lit/écrit directement la base `.kdbx` (montage Nextcloud rclone).

## Composants
- `target/release/keepass-kbd` → `~/.local/bin/keepass-kbd` : service D-Bus de session
  `org.keepasskbd.Daemon` (unité systemd utilisateur `keepass-kbd.service`).
- `qml/keepass.qml`, `qml/Kpx*.qml`, `dist/layouts_keepass.conf` →
  `/usr/share/maliit/plugins/com/jolla/layouts/` (root).
- Configuration : `~/.config/keepass-kbd/config.json`, modifiable depuis Paramètres › Système › Clavier KeePass
  (`settings/main.qml`, `settings/keepass-kbd.json` → `/usr/share/jolla-settings/`).
- Sauvegardes avant chaque écriture : `~/.local/share/keepass-kbd/backups/`.

## Auteur
Boris Solodki — solboki@solodki.fr

## Installation
1. `devel-su sh ~/keepass-kbd/install-layout.sh`  (fichiers QML, root)
2. `sh ~/keepass-kbd/install-user.sh`  (service, activation de la disposition, redémarrage de maliit)

## Sécurité
- Seul `/usr/bin/maliit-server` peut appeler le service (contrôle par PID/exécutable).
- Le mot de passe maître est saisi sur le mini-clavier interne : il n'est jamais envoyé à l'application.
- Mot de passe maître redemandé selon `relock_policy` : restart, 24h, 1h, 30min, 5min (depuis le déverrouillage) ou wake (écran éteint) ;
  aussi via le cadenas du clavier, ou si le mot de passe a changé ailleurs.
- L'application Paramètres (`settings_callers`) peut modifier les réglages et verrouiller, jamais lire la base.
- Écriture : rechargement de la dernière version, test de réécriture sans perte (balises XML +
  comparaison complète), vérification après sérialisation, sauvegarde, refus si le fichier a changé
  entre-temps, écriture dans un temporaire relu puis renommage atomique.

## Commandes
- `keepass-kbd check` : ouvre la base et teste la réécriture sans rien modifier.
- `keepass-kbd generate 24 luds` : génère un mot de passe (l, u, d, s ; `a` exclut les ambigus).

## Désinstallation
`systemctl --user disable --now keepass-kbd` puis `devel-su sh ~/keepass-kbd/uninstall-layout.sh`,
et retirer `'keepass.qml'` de `dconf read /sailfish/text_input/enabled_layouts`.
