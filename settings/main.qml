// Paramètres › Entrée de texte › Clavier KeePass
import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
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
    // Remplacé à l'installation par la version de Cargo.toml.
    readonly property string uiVersion: "@VERSION@"

    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }

    function openGroups() { pageStack.push(groupPage) }

    function reload() {
        daemon.typedCall("GetSettings", [], function(json) {
            var s = {}
            try { s = JSON.parse(json) } catch (e) {}
            page.settings = s
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

    // ── Choix du dossier des nouvelles entrées ────────────────────────
    Component {
        id: groupPage
        Page {
            id: gp
            property var groups: null
            property string current: ""

            function choose(path) {
                daemon.typedCall("SetNewEntryGroup", [{ "type": "s", "value": path }], function() {
                    page.reload()
                    pageStack.pop()
                }, function() { page.statusText = page.t("Setting not saved") })
            }

            Component.onCompleted: daemon.typedCall("ListGroups", [], function(json) {
                var r = {}
                try { r = JSON.parse(json) } catch (e) {}
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
                    PageHeader { title: page.t("Folder for new entries") }
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
                              : modelData.split("/").pop() + (modelData === "keepass-kbd" ? page.t(" (default)") : "")
                    }
                }
                VerticalScrollDecorator {}
            }
        }
    }

    // ── Choix d'un autre fichier .kdbx ────────────────────────────────
    Component {
        id: kdbxPicker
        FilePickerPage {
            title: page.t("Choose a KeePass database")
            nameFilters: [ "*.kdbx" ]
            onSelectedContentPropertiesChanged: {
                var filePath = selectedContentProperties.filePath
                if (!filePath) return
                daemon.typedCall("SetDatabase", [{ "type": "s", "value": String(filePath) }], function(json) {
                    var r = {}
                    try { r = JSON.parse(json) } catch (e) {}
                    page.statusText = r.ok ? page.t("New database saved. Unlock it from the keyboard.")
                                           : (r.error || page.t("Unable to use this file"))
                    page.reload()
                }, function() { page.statusText = page.t("keepass-kbd service unreachable") })
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
                enabled: page.settings.state === "unlocked"
                onClicked: daemon.typedCall("Lock", [], function() { page.reload() })
            }
        }

        Column {
            id: column
            width: parent.width

            PageHeader {
                title: page.t("KeePass Keyboard")
                description: page.settings.state === "unlocked" ? page.t("Database unlocked · %1 entries", page.settings.entries)
                             : page.settings.state === "missing" ? page.t("Database not found")
                             : page.loaded ? page.t("Database locked") : ""
            }

            Label {
                visible: page.statusText !== ""
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: page.statusText
                bottomPadding: Theme.paddingMedium
            }

            SectionHeader { text: page.t("Security") }

            ComboBox {
                id: policyBox
                enabled: page.loaded && !page.uninstalling
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
                    daemon.typedCall("SetRelockPolicy", [{ "type": "s", "value": id }],
                                     function() { page.statusText = ""; page.reload() },
                                     function() { page.statusText = page.t("Setting not saved") })
                }
            }

            SectionHeader { text: page.t("Database") }

            DetailItem {
                label: page.t("File")
                value: String(page.settings.database || "").split("/").pop()
            }
            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: String(page.settings.database || "")
            }
            Item { width: 1; height: Theme.paddingLarge }
            Button {
                anchors.horizontalCenter: parent.horizontalCenter
                text: page.t("Choose another file…")
                enabled: page.loaded && !page.uninstalling
                onClicked: pageStack.push(kdbxPicker)
            }
            Item { width: 1; height: Theme.paddingLarge }
            ValueButton {
                label: page.t("Folder for new entries")
                value: page.settings.new_entry_group ? page.settings.new_entry_group : page.t("Database root")
                description: page.t("Created automatically on first save if it does not exist")
                enabled: page.loaded && !page.uninstalling
                onClicked: page.openGroups()
            }

            SectionHeader { text: page.t("About") }

            DetailItem {
                label: page.t("Version")
                value: page.uiVersion + (page.settings.version && page.settings.version !== page.uiVersion
                                         ? "  " + page.t("(service %1)", page.settings.version) : "")
            }
            DetailItem { label: page.t("Author"); value: "Boris Solodki" }
            DetailItem { label: page.t("Contact"); value: "solboki@solodki.fr" }

            SectionHeader { text: page.t("Credits") }

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
