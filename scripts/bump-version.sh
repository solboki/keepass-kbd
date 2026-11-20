#!/bin/sh
# Incrémente la version : scripts/bump-version.sh patch|minor|major|X.Y.Z
# Met à jour Cargo.toml, Cargo.lock et CHANGELOG.md, puis crée le commit et l'étiquette git.
set -e
cd "$(dirname "$0")/.."
CUR=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
IFS=. read MA MI PA <<V
$CUR
V
case "$1" in
    patch) NEW="$MA.$MI.$((PA + 1))" ;;
    minor) NEW="$MA.$((MI + 1)).0" ;;
    major) NEW="$((MA + 1)).0.0" ;;
    [0-9]*.[0-9]*.[0-9]*) NEW="$1" ;;
    *) echo "usage : $0 patch|minor|major|X.Y.Z  (actuelle : $CUR)"; exit 1 ;;
esac
grep -q "^## \[Non publié\]" CHANGELOG.md || { echo "CHANGELOG.md : section « [Non publié] » manquante"; exit 1; }
sed -i "s/^version = \"$CUR\"/version = \"$NEW\"/" Cargo.toml
sed -i "s/^## \[Non publié\]/## [Non publié]\n\n## [$NEW] - $(date +%Y-%m-%d)/" CHANGELOG.md
cargo build --release -q
git add -A
git commit -q -m "Version $NEW"
git tag -a "v$NEW" -m "Version $NEW"
echo "$CUR → $NEW (étiquette v$NEW)"
