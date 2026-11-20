#!/bin/sh
# Retrait manuel des fichiers système (devel-su sh uninstall-layout.sh).
# Pour une désinstallation complète : Paramètres › Entrée de texte › Clavier KeePass › Désinstaller.
if [ "$(id -u)" != 0 ]; then echo "À lancer avec : devel-su sh $0"; exit 1; fi
sh "$(cd "$(dirname "$0")" && pwd)/dist/uninstall/uninstall-system"
