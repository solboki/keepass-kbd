# Changelog — KeePass Keyboard for Sailfish OS

Versioning follows [SemVer](https://semver.org): bug fix → `patch`, feature → `minor`,
incompatible change → `major`. Bump with `scripts/bump-version.sh patch|minor|major`
after listing the changes under “Unreleased”.

## [Unreleased]

## [1.0.1] - 2026-11-20
### Fixed
- Choosing the database file failed for folders on FUSE mounts without `allow_other` (rclone, sshfs…):
  the Settings app runs with the `privileged` group and cannot read them. The file browser is now
  provided by the service, which runs as the user (new `ListDir` D-Bus method).
- Titles of the folder and file chooser pages were empty.
- Upgrades left the previous service running (BusyBox `pkill -x` does not match it): the package
  scripts now stop it with `systemctl --user` in each session, with `pkill -f` as a fallback.
### Added
- First launch: while no database is configured, the KeePass layout opens its settings page once and
  the file browser opens automatically; the layout also shows a “Choose the database file…” button.

## [1.0.0] - 2026-11-20
First public release.
### Added
- RPM package (`scripts/build-rpm.sh`, built with cargo-generate-rpm): files installed under `/usr`,
  service started on demand through D-Bus activation, layout enabled on install and removed on uninstall.
- English documentation, GPL-3.0-or-later license.
### Changed
- No default database: choose your `.kdbx` file in the settings page.
- Uninstall from the settings page removes the package (`rpm -e`) or a manual install.
- Polkit rule for the uninstall script limited to regular users (`users` group).

## [0.11.0] - 2026-11-20
### Added
- Localisation: English (default), French, German, Spanish, Italian, Finnish, Swedish, Dutch, Russian,
  following the phone language (keyboard, settings, service messages).
- Mini keyboard adapted to the language (AZERTY, QWERTZ or QWERTY, language accents).
- Uninstall from the settings page, optionally deleting settings and backups.
- `scripts/mkqm.py`: Qt `.qm` catalogs without lrelease.
### Fixed
- Master password and form fields: the cursor can be placed by tapping (or dragging); typing and erasing happen at the cursor.

## [0.10.0] - 2026-11-20
### Added
- Application icon, used for notifications.
### Changed
- Generator: “Insert” and “Save…” merged into a single **Use** button that types the password and opens the save page.

## [0.9.0] - 2026-11-20
### Added
- Settings: choose the folder for new entries (existing or new, nested paths allowed); created on first save.
### Changed
- New entries go to a `keepass-kbd` folder by default instead of the root.

## [0.8.1] - 2026-11-20
### Fixed
- Saving refused on KeePassXC databases: two harmless differences are now tolerated by the fidelity check
  (obsolete KDBX 3 `HeaderHash`, explicit default `QualityCheck`).
- Saving too slow for the D-Bus call on databases with a heavy key derivation: preparation and writing run
  in the background and the result is reported by a notification.
### Changed
- After saving, the keyboard returns to the previous layout and closes.
- Fidelity check run in advance after each unlock or reload.
- Save failures logged to `~/.local/share/keepass-kbd/errors.log` (no secrets).

## [0.8.0] - 2026-11-20
### Added
- New entry: title suggested from the app's `.desktop` name or the website, username reused from the page.
- System notification after saving (or on failure).
### Changed
- Save form in Sailfish style: title, username, hidden password (eye), URL, then the save button.

## [0.7.1] - 2026-11-20
### Fixed
- “KeePass Keyboard” entry missing from *Settings › Text input* (the `settings=` key needs an input handler).
### Changed
- The gear icon always stays on the right edge.

## [0.7.0] - 2026-11-20
### Added
- “KeePass Keyboard” entry in *Settings › Text input*; versioning tools and changelog.
### Changed
- Master password field in Sailfish style; compact rectangular confirm button.
### Fixed
- Settings page could not reach the service (the Settings app runs with the `privileged` group).

## [0.6.0] - 2026-11-20
### Added
- Backspace key acting on the app's field; settings page (lock policy, database file, about, credits); gear icon.
### Changed
- “+” icon for the generator; relock timed from unlocking.

## [0.5.0] - 2026-11-20
### Added
- Return to the previous layout when the keyboard closes; suggestions for AppSupport apps from the package name.

## [0.4.0] - 2026-11-20
### Added
- Suggestions for the current website or app; graphical interface (icons, avatars, coloured generator, eye).

## [0.3.0] - 2026-11-20
### Added
- One-tap fill of username and password; show master password.
### Changed
- Layout: search, suggestions, then insert buttons.

## [0.2.0] - 2026-11-20
### Fixed
- Mini keyboard missing on the unlock screen; exclusive D-Bus name.

## [0.1.0] - 2026-11-20
### Added
- `keepass-kbd` service (Rust): direct `.kdbx` access, automatic reload, generator, verified writes with backups.
- “KeePass” Maliit keyboard layout.
