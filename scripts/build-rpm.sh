#!/bin/sh
# Builds the KeePass Keyboard RPM (native build on the phone, or any aarch64 Sailfish SDK target).
#   scripts/build-rpm.sh    → target/generate-rpm/keepass-kbd-<version>-1.<arch>.rpm
set -e
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
STAGE=target/rpm-stage
rm -rf "$STAGE"; mkdir -p "$STAGE"

cargo build --release
strip -s target/release/keepass-kbd 2>/dev/null || true

# QML files with the version stamped in.
for f in qml/keepass.qml settings/main.qml; do
    sed "s/@VERSION@/$VERSION/g" "$f" > "$STAGE/$(basename "$(dirname "$f")")-$(basename "$f")"
done

# Settings title translations (.qm, generated without lrelease).
python3 scripts/mkqm.py "$STAGE/settings-keepass-kbd_eng_en.qm" "settings_keepass_kbd-he-title=KeePass Keyboard"
for pair in "fr=Clavier KeePass" "de=KeePass-Tastatur" "es=Teclado KeePass" "it=Tastiera KeePass" \
            "fi=KeePass-näppäimistö" "sv=KeePass-tangentbord" "nl=KeePass-toetsenbord" "ru=Клавиатура KeePass"; do
    python3 scripts/mkqm.py "$STAGE/settings-keepass-kbd-${pair%%=*}.qm" "settings_keepass_kbd-he-title=${pair#*=}"
done

cargo generate-rpm
ls -l target/generate-rpm/*.rpm
