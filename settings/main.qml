// Paramètres › Entrée de texte › Clavier KeePass
// Sections : Verrouillage, Base des mots de passe, Base des codes (OTP), À propos, Désinstallation.
import QtQuick 2.0
import Sailfish.Silica 1.0
import Nemo.DBus 2.0
import "KpxStrings.js" as S

Page {
    id: page

    property var settings: ({})
    property var policies: ["restart", "24h", "1h", "30min", "5min", "wake"]
    readonly property var policyLabels: ({
        "restart": "on every restart", "24h": "every 24 hours", "1h": "every hour",
        "30min": "every 30 minutes", "5min": "every 5 minutes", "wake": "on every wake-up"
    })
    property string statusText: ""
    property bool loaded: false
    property bool uninstalling: false
    property bool busy: false
    readonly property bool editable: loaded && !uninstalling && !busy
    readonly property bool mainEnabled: settings.database_enabled !== false
    readonly property bool otpEnabled: !!settings.totp_enabled
    readonly property bool otpSeparate: !!settings.otp_database
    // Premier lancement (aucune base choisie) : ouvrir le choix du fichier automatiquement.
    property bool autoPicked: false
    Timer {
        id: autoPickTimer
        interval: 200
        repeat: true
        onTriggered: if (page.status === PageStatus.Active && !pageStack.busy) { stop(); page.chooseDatabase("main") }
    }
    // Remplacé à l'installation par la version de Cargo.toml.
    readonly property string uiVersion: "@VERSION@"

    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }
    function fileName(p) { return String(p || "").split("/").pop() }

    // Appel au service ; done reçoit la réponse JSON décodée ({ok:false, error} si injoignable).
    function call(method, args, done) {
        daemon.typedCall(method, args, function(json) {
            var r = {}
            try { r = JSON.parse(json) } catch (e) { r = { ok: true, value: json } }
            if (done) done(r)
        }, function() { if (done) done({ ok: false, error: page.t("keepass-kbd service unreachable") }) })
    }
    function str(v) { return { "type": "s", "value": v } }
    function bool(v) { return { "type": "b", "value": v } }

    function stateText(state, entries) {
        return state === "unlocked" ? (entries !== undefined && entries !== null ? page.t("Unlocked · %1 entries", entries) : page.t("Unlocked"))
             : state === "locked" ? page.t("Locked")
             : state === "missing" ? page.t("Not found")
             : state === "disabled" ? page.t("Disabled")
             : ""
    }

    // Choix d'une base existante : "main" (mots de passe) ou "otp" (codes).
    function chooseDatabase(target) {
        var p = pageStack.push(Qt.resolvedUrl("FilePicker.qml"),
                               { daemon: daemon, kind: "kdbx",
                                 title: target === "main" ? t("Password database") : t("One-time codes database (OTP)") })
        p.chosen.connect(function(path) {
            call(target === "main" ? "SetDatabase" : "SetOtpDatabase", [str(path)], function(r) {
                page.statusText = !r.ok ? (r.error || page.t("Unable to use this file"))
                                : page.t("Database chosen. If it uses a key file, choose it below.")
                page.reload()
            })
        })
    }

    // Création d'une base (et de son fichier clé) : la boîte se ferme, on revient ici, puis la
    // base et le fichier clé sont créés et sélectionnés.
    function newDatabase(target) {
        var d = pageStack.push(Qt.resolvedUrl("DatabaseCreateDialog.qml"),
                               { daemon: daemon, settings: settings, target: target })
        d.accepted.connect(function() {
            page.createDatabase(target, d.dbPath, d.password, d.keyPath, d.usesKey && d.newKey, d.keyOnly)
        })
    }
    function createDatabase(target, dbPath, password, keyPath, newKey, keyOnly) {
        busy = true
        statusText = t("Creating the database…")
        var fail = function(r) { page.busy = false; page.statusText = r.error || page.t("Setting not saved"); page.reload() }
        var steps = [
            function(next) { if (newKey) call("CreateKeyfile", [str(keyPath)], next); else next({ ok: true }) },
            function(next) { call("CreateDatabase", [str(dbPath), str(password), str(keyPath)], next) },
            function(next) { call(target === "main" ? "SetDatabase" : "SetOtpDatabase", [str(dbPath)], next) },
            function(next) { call("SetKeyfile", [str(target), str(keyPath)], next) },
            function(next) { if (target === "otp") call("SetOtpKeyfileOnly", [bool(keyOnly)], next); else next({ ok: true }) }
        ]
        var run = function(i) {
            if (i === steps.length) {
                page.busy = false
                page.statusText = keyPath !== ""
                        ? page.t("Database created and selected. Keep a copy of the key file %1 elsewhere: without it, the database cannot be opened.", keyPath)
                        : page.t("Database created and selected.")
                page.reload()
                return
            }
            steps[i](function(r) { if (r.ok) run(i + 1); else fail(r) })
        }
        run(0)
    }

    // Fichier clé de la base des mots de passe ("main") ou de la base des codes ("otp").
    function chooseKeyfile(target) {
        var p = pageStack.push(Qt.resolvedUrl("FilePicker.qml"),
                               { daemon: daemon, kind: "key", allowNone: true, title: t("Key file") })
        p.chosen.connect(function(path) {
            call("SetKeyfile", [str(target), str(path)], function(r) {
                page.statusText = r.ok ? page.t("Key file saved. Unlock the database again from the keyboard.")
                                       : (r.error || page.t("Unable to use this file"))
                page.reload()
            })
        })
    }

    function setAndReload(method, args) {
        call(method, args, function(r) {
            page.statusText = r.ok === false ? (r.error || page.t("Setting not saved")) : ""
            page.reload()
        })
    }

    function reload() {
        daemon.typedCall("GetSettings", [], function(json) {
            var s = {}
            try { s = JSON.parse(json) } catch (e) {}
            page.settings = s
            if (!s.database && s.database_enabled !== false && !page.autoPicked) {
                page.autoPicked = true
                autoPickTimer.start()
            }
            var i = page.policies.indexOf(s.relock_policy)
            if (i >= 0) policyBox.currentIndex = i
            page.loaded = true
        }, function(err) {
            page.loaded = false
            if (!page.uninstalling) page.statusText = page.t("keepass-kbd service unreachable")
        })
    }

    DBusInterface {
        id: daemon
        bus: DBus.SessionBus
        service: "org.keepasskbd.Daemon"
        path: "/org/keepasskbd/Daemon"
        iface: "org.keepasskbd.Daemon1"
        signalsEnabled: true
        watchServiceStatus: true
        onStatusChanged: page.reload()
        function changed() { page.reload() }
    }

    Component.onCompleted: reload()

    // ── Choix du dossier des nouvelles entrées (target : "main" ou "otp") ──
    Component {
        id: groupPage
        Page {
            id: gp
            property string target: "main"
            property var groups: null
            property string current: ""

            function choose(path) {
                page.call("SetNewEntryGroup", [page.str(gp.target), page.str(path)], function(r) {
                    if (r.ok === false) page.statusText = page.t("Setting not saved")
                    page.reload()
                    pageStack.pop()
                })
            }

            Component.onCompleted: page.call("ListGroups", [page.str(gp.target)], function(r) {
                gp.current = r.current || ""
                var list = r.groups || null
                if (list && list.indexOf("keepass-kbd") < 0) list.splice(1, 0, "keepass-kbd")
                gp.groups = list
            })

            SilicaListView {
                anchors.fill: parent
                model: gp.groups || []
                header: Column {
                    width: parent.width
                    PageHeader {
                        // « page » désigne ici la propriété de PageHeader : passer par S.tr.
                        title: S.tr(S.lang(Qt.locale().name), "Folder for new entries")
                        description: S.tr(S.lang(Qt.locale().name), gp.target === "otp" ? "One-time codes database (OTP)" : "Password database")
                    }
                    TextField {
                        width: parent.width
                        label: page.t("New folder (e.g. Internet/Apps)")
                        placeholderText: page.t("Name of a new folder")
                        EnterKey.enabled: text.trim().length > 0
                        EnterKey.iconSource: "image://theme/icon-m-enter-accept"
                        EnterKey.onClicked: gp.choose(text)
                    }
                    Label {
                        visible: gp.groups === null
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        wrapMode: Text.Wrap
                        color: Theme.highlightColor
                        text: page.t("Unlock the database from the KeePass keyboard to show its folders.")
                        bottomPadding: Theme.paddingLarge
                    }
                    SectionHeader { visible: gp.groups !== null; text: page.t("Database folders") }
                }
                delegate: ListItem {
                    contentHeight: Theme.itemSizeSmall
                    onClicked: gp.choose(modelData)
                    Icon {
                        id: folderIcon
                        x: Theme.horizontalPageMargin + (modelData === "" ? 0 : (modelData.split("/").length - 1) * Theme.paddingLarge)
                        anchors.verticalCenter: parent.verticalCenter
                        source: modelData === "" ? "image://theme/icon-m-home" : "image://theme/icon-m-folder"
                        color: modelData === gp.current ? Theme.highlightColor : Theme.primaryColor
                    }
                    Label {
                        anchors { left: folderIcon.right; leftMargin: Theme.paddingMedium; right: parent.right
                                  rightMargin: Theme.horizontalPageMargin; verticalCenter: parent.verticalCenter }
                        truncationMode: TruncationMode.Fade
                        color: modelData === gp.current ? Theme.highlightColor : Theme.primaryColor
                        text: modelData === "" ? page.t("Database root")
                              : modelData.split("/").pop() + (modelData === "keepass-kbd" && gp.target === "main" ? page.t(" (default)") : "")
                    }
                }
                VerticalScrollDecorator {}
            }
        }
    }

    // ── Confirmation de la désinstallation ────────────────────────────
    Component {
        id: uninstallDialog
        Dialog {
            id: dlg
            canAccept: page.loaded
            Column {
                width: parent.width
                spacing: Theme.paddingMedium
                DialogHeader { acceptText: page.t("Uninstall") }
                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeLarge
                    color: Theme.highlightColor
                    text: page.t("Uninstall KeePass Keyboard")
                }
                Label {
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    color: Theme.secondaryHighlightColor
                    text: page.t("Removes the keyboard layout, its settings pages and the background service. Your KeePass database is never modified.")
                }
                TextSwitch { id: removeSettings; text: page.t("Also delete settings") }
                TextSwitch {
                    id: removeBackups
                    text: page.t("Also delete local backups")
                    description: "~/.local/share/keepass-kbd/backups"
                }
            }
            onAccepted: {
                page.uninstalling = true
                page.statusText = page.t("Uninstalling… The keyboard will restart.")
                daemon.typedCall("Uninstall", [{ "type": "b", "value": removeSettings.checked },
                                               { "type": "b", "value": removeBackups.checked }],
                                 function(json) {
                                     var r = {}
                                     try { r = JSON.parse(json) } catch (e) {}
                                     if (!r.ok) {
                                         page.uninstalling = false
                                         page.statusText = page.t("Uninstall failed") + (r.error ? " : " + r.error : "")
                                     }
                                 }, function() {
                                     page.uninstalling = false
                                     page.statusText = page.t("Uninstall failed")
                                 })
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: page.t("Lock now")
                enabled: page.settings.state === "unlocked" || page.settings.otp_state === "unlocked"
                onClicked: daemon.typedCall("Lock", [], function() { page.reload() })
            }
        }

        Column {
            id: column
            width: parent.width

            PageHeader { title: page.t("KeePass Keyboard") }

            Label {
                visible: page.statusText !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: page.statusText
                bottomPadding: Theme.paddingMedium
            }

            // ── Verrouillage ──────────────────────────────────────────
            SectionHeader { text: page.t("Locking") }

            DetailItem {
                label: page.t("Password database")
                value: page.loaded ? page.stateText(page.settings.state, page.settings.entries) : ""
            }
            DetailItem {
                label: page.t("One-time codes database (OTP)")
                value: !page.loaded ? ""
                       : !page.otpEnabled ? page.t("Disabled")
                       : !page.otpSeparate ? page.t("In the password database")
                       : page.stateText(page.settings.otp_state)
            }
            ComboBox {
                id: policyBox
                enabled: page.editable
                label: page.t("Ask for the master password again")
                description: page.t("The phone stays protected by its PIN and fingerprint. “On every wake-up” locks the database as soon as the screen turns off.")
                menu: ContextMenu {
                    Repeater {
                        model: page.policies
                        MenuItem { text: page.t(page.policyLabels[modelData]) }
                    }
                }
                onCurrentIndexChanged: {
                    if (!page.loaded || currentIndex < 0) return
                    var id = page.policies[currentIndex]
                    if (id === page.settings.relock_policy) return
                    page.setAndReload("SetRelockPolicy", [page.str(id)])
                }
            }

            // ── Base des mots de passe ────────────────────────────────
            SectionHeader { text: page.t("Password database") }

            TextSwitch {
                enabled: page.editable
                automaticCheck: false
                checked: page.mainEnabled
                text: page.t("Enabled")
                description: page.t("Turned off, the keyboard no longer opens this database.")
                onClicked: page.setAndReload("SetDatabaseEnabled", [page.bool(!checked)])
            }
            Column {
                width: parent.width
                visible: page.mainEnabled
                DetailItem { label: page.t("File"); value: String(page.settings.database || "") !== "" ? page.fileName(String(page.settings.database || "")) : page.t("None") }
                Label {
                    visible: String(page.settings.database || "") !== ""
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.WrapAnywhere
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: String(page.settings.database || "")
                }
                Item { width: 1; height: Theme.paddingMedium }
                Column {
                    width: parent.width
                    spacing: Theme.paddingMedium
                    Button { anchors.horizontalCenter: parent.horizontalCenter; preferredWidth: Theme.buttonWidthLarge
                             text: page.t("Choose another file…"); enabled: page.editable; onClicked: page.chooseDatabase("main") }
                    Button { anchors.horizontalCenter: parent.horizontalCenter; preferredWidth: Theme.buttonWidthLarge
                             text: page.t("Create a new database…"); enabled: page.editable; onClicked: page.newDatabase("main") }
                }
                Item { width: 1; height: Theme.paddingMedium }
                ValueButton {
                    label: page.t("Key file")
                    value: page.settings.keyfile ? page.fileName(page.settings.keyfile) : page.t("None")
                    description: page.t("If the database is also protected by a key file")
                    enabled: page.editable
                    onClicked: page.chooseKeyfile("main")
                }
                ValueButton {
                    label: page.t("Folder for new entries")
                    value: page.settings.new_entry_group ? page.settings.new_entry_group : page.t("Database root")
                    description: page.t("Created automatically on first save if it does not exist")
                    enabled: page.editable
                    onClicked: pageStack.push(groupPage, { target: "main" })
                }
            }

            // ── Base des codes à usage unique ─────────────────────────
            SectionHeader { text: page.t("One-time codes database (OTP)") }

            TextSwitch {
                enabled: page.editable
                automaticCheck: false
                checked: page.otpEnabled
                text: page.t("Enabled")
                description: page.t("Adds a “Code” button to the keyboard for entries that have a two-factor code (otp field of KeePassXC and KeePassDX, TimeOtp fields of KeePass 2). The secret key never leaves the service.")
                onClicked: page.setAndReload("SetTotpEnabled", [page.bool(!checked)])
            }
            Column {
                width: parent.width
                visible: page.otpEnabled
                DetailItem { label: page.t("File"); value: String(page.settings.otp_database || "") !== "" ? page.fileName(String(page.settings.otp_database || "")) : page.t("Password database") }
                Label {
                    visible: String(page.settings.otp_database || "") !== ""
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.WrapAnywhere
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryColor
                    text: String(page.settings.otp_database || "")
                }
                Item { width: 1; height: Theme.paddingMedium }
                Column {
                    width: parent.width
                    spacing: Theme.paddingMedium
                    Button { anchors.horizontalCenter: parent.horizontalCenter; preferredWidth: Theme.buttonWidthLarge
                             text: page.t("Choose another file…"); enabled: page.editable; onClicked: page.chooseDatabase("otp") }
                    Button { anchors.horizontalCenter: parent.horizontalCenter; preferredWidth: Theme.buttonWidthLarge
                             text: page.t("Create a new database…"); enabled: page.editable; onClicked: page.newDatabase("otp") }
                    Button {
                        anchors.horizontalCenter: parent.horizontalCenter
                        preferredWidth: Theme.buttonWidthLarge
                        visible: page.otpSeparate
                        text: page.t("Use the password database")
                        enabled: page.editable
                        onClicked: page.call("SetOtpDatabase", [page.str("")], function(r) {
                            page.statusText = r.ok ? page.t("One-time codes are read from the password database.")
                                                   : (r.error || page.t("Setting not saved"))
                            page.reload()
                        })
                    }
                }
                Label {
                    visible: !page.otpSeparate
                    x: Theme.horizontalPageMargin
                    width: parent.width - 2 * Theme.horizontalPageMargin
                    wrapMode: Text.Wrap
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: Theme.secondaryHighlightColor
                    topPadding: Theme.paddingMedium
                    text: page.t("Keeping the one-time codes in another database, with another password or a key file, means that someone who learns your master password still lacks the second factor.")
                }
                Item { width: 1; height: Theme.paddingMedium }
                ValueButton {
                    visible: page.otpSeparate
                    label: page.t("Key file")
                    value: page.settings.otp_keyfile ? page.fileName(page.settings.otp_keyfile) : page.t("None")
                    description: page.t("If the database is also protected by a key file")
                    enabled: page.editable
                    onClicked: page.chooseKeyfile("otp")
                }
                TextSwitch {
                    visible: page.otpSeparate && !!page.settings.otp_keyfile
                    enabled: page.editable
                    automaticCheck: false
                    checked: !!page.settings.otp_keyfile_only
                    text: page.t("Key file only")
                    description: page.t("The codes database opens without a password, with the key file alone.")
                    onClicked: page.setAndReload("SetOtpKeyfileOnly", [page.bool(!checked)])
                }
                ValueButton {
                    visible: page.otpSeparate
                    label: page.t("Folder for new entries")
                    value: page.settings.otp_new_entry_group ? page.settings.otp_new_entry_group : page.t("Database root")
                    description: page.t("Created automatically on first save if it does not exist")
                    enabled: page.editable
                    onClicked: pageStack.push(groupPage, { target: "otp" })
                }

                // Ajout du code d'une entrée : clé, lien otpauth://, capture d'écran ou appareil photo.
                BackgroundItem {
                    enabled: page.editable
                    height: Theme.itemSizeMedium
                    onClicked: pageStack.push(Qt.resolvedUrl("OtpEntriesPage.qml"))
                    Icon {
                        id: otpAddIcon
                        x: Theme.horizontalPageMargin
                        anchors.verticalCenter: parent.verticalCenter
                        source: "image://theme/icon-m-timer"
                        color: parent.highlighted ? Theme.highlightColor : Theme.primaryColor
                    }
                    Column {
                        anchors { left: otpAddIcon.right; leftMargin: Theme.paddingMedium; right: parent.right
                                  rightMargin: Theme.horizontalPageMargin; verticalCenter: parent.verticalCenter }
                        Label {
                            width: parent.width
                            truncationMode: TruncationMode.Fade
                            color: parent.parent.highlighted ? Theme.highlightColor : Theme.primaryColor
                            text: page.t("Add a one-time code to an entry")
                        }
                        Label {
                            width: parent.width
                            truncationMode: TruncationMode.Fade
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: parent.parent.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                            text: page.t("Secret key, screenshot or camera")
                        }
                    }
                }
            }

            // ── À propos (et crédits) ─────────────────────────────────
            SectionHeader { text: page.t("About") }

            DetailItem {
                label: page.t("Version")
                value: page.uiVersion + (page.settings.version && page.settings.version !== page.uiVersion
                                         ? "  " + page.t("(service %1)", page.settings.version) : "")
            }
            DetailItem { label: page.t("Author"); value: "Boris Solodki" }
            DetailItem { label: page.t("Contact"); value: "solboki@solodki.fr" }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeSmall
                color: Theme.highlightColor
                topPadding: Theme.paddingLarge
                bottomPadding: Theme.paddingSmall
                text: page.t("Credits")
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                textFormat: Text.PlainText
                text: page.t("Background service (Rust):") + "\n"
                      + "• " + page.t("keepass-rs — reading and writing KDBX databases (MIT)") + "\n"
                      + "• " + page.t("zbus — D-Bus communication (MIT)") + "\n"
                      + "• " + page.t("rust-argon2, sha2, rand, zeroize — cryptography (MIT / Apache-2.0)") + "\n"
                      + "• serde, serde_json, chrono, uuid (MIT / Apache-2.0)\n\n"
                      + page.t("Interface:") + "\n"
                      + "• " + page.t("Sailfish OS, Silica and Maliit — Jolla") + "\n"
                      + "• Qt 5 — The Qt Company (LGPL)\n"
                      + "• " + page.t("FUTO Keyboard for Sailfish — detection of the current site and app") + "\n\n"
                      + page.t("KeePass format: KeePass project by Dominik Reichl; compatible with KeePassXC and KeePassDX.")
                bottomPadding: Theme.paddingLarge
            }

            // ── Désinstallation ───────────────────────────────────────
            SectionHeader { text: page.t("Uninstall") }

            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.t("Uninstall KeePass Keyboard")
                enabled: page.loaded && !page.uninstalling
                onClicked: pageStack.push(uninstallDialog)
            }
            Item { width: 1; height: Theme.paddingLarge * 2 }
        }
        VerticalScrollDecorator {}
    }
}
