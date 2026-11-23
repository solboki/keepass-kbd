#!/bin/sh
# Builds the KeePass Keyboard RPM(s).
#   scripts/build-rpm.sh [aarch64|armv7hl|i486|all]   (default: aarch64)
#   → target/generate-rpm/keepass-kbd-<version>-1.<arch>.rpm
# aarch64 is built natively (phone or aarch64 SDK target). armv7hl and i486 are
# cross-compiled with Zig as C compiler/linker (scripts/cross/zigcc-*), linked
# against glibc 2.30 (Sailfish OS 4.0+); needs:
#   rustup target add armv7-unknown-linux-gnueabihf i686-unknown-linux-gnu
#   Zig 0.14.1 in ~/.local/opt/zig-aarch64-linux-0.14.1 (or ZIG=/path/to/zig)
set -e
cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
STAGE=target/rpm-stage
CROSS=$PWD/scripts/cross

ARCHES=${1:-aarch64}
[ "$ARCHES" = all ] && ARCHES="aarch64 armv7hl i486"

rm -rf "$STAGE"; mkdir -p "$STAGE"

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

for arch in $ARCHES; do
    case $arch in
        aarch64)
            cargo build --release
            strip -s target/release/keepass-kbd 2>/dev/null || true
            cargo generate-rpm
            ;;
        armv7hl|i486)
            if [ $arch = armv7hl ]; then
                triple=armv7-unknown-linux-gnueabihf; cc=$CROSS/zigcc-arm-linux-gnueabihf
            else
                triple=i686-unknown-linux-gnu; cc=$CROSS/zigcc-x86-linux-gnu
            fi
            var=$(echo $triple | tr 'a-z-' 'A-Z_')
            env "CC_$(echo $triple | tr - _)=$cc" "AR_$(echo $triple | tr - _)=$CROSS/zigar" \
                "CARGO_TARGET_${var}_LINKER=$cc" \
                cargo build --release --target $triple
            # Zig links with -s already when the profile strips; host strip can't handle foreign ELF.
            cargo generate-rpm --target $triple --arch $arch
            mkdir -p target/generate-rpm
            cp target/$triple/generate-rpm/keepass-kbd-$VERSION-1.$arch.rpm target/generate-rpm/
            ;;
        *) echo "unknown arch: $arch (aarch64|armv7hl|i486|all)" >&2; exit 1 ;;
    esac
done
ls -l target/generate-rpm/*.rpm
