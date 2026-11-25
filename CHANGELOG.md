# Changelog — KeePass Keyboard for Sailfish OS

Versioning follows [SemVer](https://semver.org): bug fix → `patch`, feature → `minor`,
incompatible change → `major`. Bump with `scripts/bump-version.sh patch|minor|major`
after listing the changes under “Unreleased”.

## [Unreleased]
### Changed
- The RPMs are now built by GitHub Actions (`.github/workflows/build.yml`): tests and the three
  packages on every push, and on a `vX.Y.Z` tag the packages are attached to the release. Outside
  Sailfish OS (or with `KPX_CROSS=1`), `scripts/build-rpm.sh` cross-compiles aarch64 with Zig too,
  so the binary does not depend on the glibc of the build machine.

## [1.1.3] - 2026-11-25
### Added
- RPMs for armv7hl (32-bit ARM) and i486 (x86), cross-compiled with Zig: `scripts/build-rpm.sh armv7hl|i486|all`.
### Fixed
- The service froze (no answer on D-Bus, keyboard stuck) when the database was on a network mount
  that stopped responding (rclone, sshfs…). File accesses (database, key file) now give up after
  10 s (3 s for a `stat`) with “the file is not responding”, and only one blocked access per file is
  kept waiting. Unlocking the password database runs off the D-Bus loop, and the periodic check reads
  the file without holding the service lock; if the file cannot be read, the database already in
  memory stays usable and the check is retried later.

## [1.1.2] - 2026-11-21
### Added
- Secondary URLs are used for suggestions, search and matching with the one-time codes database:
  `KP2A_URL`, `KP2A_URL_1`… (Keepass2Android, KeePassXC “additional URLs”), fields named like a URL
  (`URL2`, `url_1`…) and custom fields whose value is an `http(s)://` or `androidapp://` link; an
  `androidapp://package` secondary URL matches that app.
### Changed
- In a number field (two-factor code), tapping an entry types its code instead of its username; an
  entry without a known code is only selected.
- Preselection: the account whose username was typed on the page first, then, in a number field, an
  account that has a code. An entry tapped by hand stays selected on the next pages of the same site.
- The search filter is cleared when the keyboard closes and when the site or app changes.
- One-time codes are typed digit by digit, like the Jolla number pad (some pages ignored a code sent
  in one block).
- Suggestions are recomputed after the codes database is unlocked.
### Fixed
- Sailfish Browser: the current site was not found (the field context of FUTO is empty there, and the
  “active tab” saved by the browser is stale). The service now reads the last page visited in an open
  tab from the browser database (`sailfish-browser.sqlite`, read-only; only the origin is returned,
  new `BrowserOrigin` D-Bus method). New dependency: `rusqlite` (bundled SQLite).
- Separate codes database without a username: the account of the `otpauth` link now only confirms a
  match; it rules one out only when both are different e-mail addresses.

## [1.1.1] - 2026-11-21
### Fixed
- Codes of a separate one-time codes database were not found for entries created elsewhere (other
  app, KeePassXC import): the site is now matched across URL, title and the issuer of the `otpauth`
  link (`facebook.com` ↔ “Facebook”), and the account also from the `otpauth` link (`boris@mail.fr` ↔
  `boris`; missing on one side = accepted). A different account of the same site is still never used.

## [1.1.0] - 2026-11-20
### Added
- One-time codes (TOTP), off by default: enable *One-time codes (TOTP)* in the settings and a *Code (N s)*
  button types the current code of entries that have one (`otp` URI of KeePassXC / KeePassDX, KeePass 2
  `TimeOtp-*` fields, legacy `TOTP Seed` / `TOTP Settings`; SHA-1/256/512, Steam). The secret key stays in
  the service; only the code is sent to the keyboard (new `Totp` and `SetTotpEnabled` D-Bus methods).
- Add a two-factor code to an entry, from the keyboard (*+ Code* button) or from the settings
  (*Add a one-time code to an entry*): secret key typed or pasted, `otpauth://` link, screenshot of the
  QR code, or camera scan (settings). The current code is shown to finish the activation on the site;
  the code is saved in the `otp` field (KeePassXC / KeePassDX format) with the previous version kept in
  the entry history. New D-Bus methods `OtpPreview`, `SetOtp`, `OtpFromImage`, `RecentImages`,
  `OtpEntries`, `OtpScanPath`; the Settings app may now list entry titles and usernames for this.
- Separate database for one-time codes (optional): protected by its own password, password and key
  file, or key file only; chosen or created from the settings, unlocked from the keyboard when a code is
  needed, locked with the password database. Codes added from the keyboard or the settings go into
  it, linked to the password entry (`KeePassKbd-Link` field); existing entries are matched by website
  and username, then by title and username. Backups in `backups-otp`.
- Key files: choose the key file of the password database in the settings; create key files (KeePass
  XML 2.0). New databases use Argon2id with 64 MiB. New D-Bus methods `UnlockOtp`, `SetOtpDatabase`,
  `SetKeyfile`, `SetOtpKeyfileOnly`, `ListFiles`, `CreateKeyfile`, `CreateDatabase`.
- Settings reorganised into *Locking* (state of both databases, re-lock delay), *Password database*,
  *One-time codes database (OTP)*, *About* (with the credits) and *Uninstall*. Each database section
  has an on/off switch, the file and its path, *Choose another file…*, *Create a new database…*, the key
  file and the folder for new entries. A database created here, and its new key file, are selected
  right away and the settings page is shown again.
- The password database can be turned off (`SetDatabaseEnabled`); the keyboard then shows it as
  disabled. Folder for new entries of the codes database (`ListGroups` and `SetNewEntryGroup` now take
  the target database, "main" or "otp").
- KeePass key in the Jolla number and phone pads: code fields open one of these pads, which allow no
  layout change; a KeePass key (bottom left) now opens the KeePass layout, and typing the code returns to
  the pad. The package adds a few marked lines to the pad files of `jolla-keyboard`
  (`/usr/libexec/keepass-kbd/numpad-patch`); `keepass-kbd-numpad.service` puts them back at boot after a
  Sailfish OS update, and uninstalling restores the original files.
### Fixed
- New settings texts shown in English after an update: the Settings app, kept in memory, is now
  closed on install so that it reloads the translations.

## [1.0.2] - 2026-11-20
### Changed
- The database file is now chosen directly in the KeePass layout (first launch and “Choose the database
  file…” button): you stay in the current app and can unlock right after choosing, instead of being sent
  to the Settings app.

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
