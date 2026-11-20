// Page Paramètres › Système › Clavier KeePass
import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Pickers 1.0
import Nemo.DBus 2.0

Page {
    id: page

    property var settings: ({})
    property var policies: []
    property string statusText: ""
    property bool loaded: false
    // Remplacé à l'installation par la version de Cargo.toml.
    readonly property string uiVersion: "@VERSION@"

    function reload() {
        daemon.typedCall("GetSettings", [], function(json) {
            var s = {}
            try { s = JSON.parse(json) } catch (e) {}
            page.settings = s
            page.policies = s.policies || []
            for (var i = 0; i < page.policies.length; ++i)
                if (page.policies[i].id === s.relock_policy) policyBox.currentIndex = i
            page.loaded = true
        }, function(err) {
            page.loaded = false
            page.statusText = "Service keepass-kbd injoignable"
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

    Component {
        id: kdbxPicker
        FilePickerPage {
            title: "Choisir une base KeePass"
            nameFilters: [ "*.kdbx" ]
            onSelectedContentPropertiesChanged: {
                var filePath = selectedContentProperties.filePath
                if (!filePath) return
                daemon.typedCall("SetDatabase", [{ "type": "s", "value": String(filePath) }], function(json) {
                    var r = {}
                    try { r = JSON.parse(json) } catch (e) {}
                    page.statusText = r.ok ? "Nouvelle base enregistrée. Déverrouillez-la depuis le clavier."
                                           : (r.error || "Impossible d'utiliser ce fichier")
                    page.reload()
                }, function() { page.statusText = "Service keepass-kbd injoignable" })
            }
        }
    }

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: column.height + Theme.paddingLarge

        PullDownMenu {
            MenuItem {
                text: "Verrouiller maintenant"
                enabled: page.settings.state === "unlocked"
                onClicked: daemon.typedCall("Lock", [], function() { page.reload() })
            }
        }

        Column {
            id: column
            width: parent.width

            PageHeader {
                title: "Clavier KeePass"
                description: page.settings.state === "unlocked"
                             ? "Base déverrouillée · " + page.settings.entries + " entrées"
                             : page.settings.state === "missing" ? "Base introuvable"
                             : page.loaded ? "Base verrouillée" : ""
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

            SectionHeader { text: "Sécurité" }

            ComboBox {
                id: policyBox
                enabled: page.loaded
                label: "Redemander le mot de passe maître"
                description: "Le téléphone reste protégé par son code et l'empreinte. "
                             + "« À chaque sortie de veille » verrouille la base dès que l'écran s'éteint."
                menu: ContextMenu {
                    Repeater {
                        model: page.policies
                        MenuItem { text: modelData.label }
                    }
                }
                onCurrentIndexChanged: {
                    if (!page.loaded || currentIndex < 0 || currentIndex >= page.policies.length) return
                    var id = page.policies[currentIndex].id
                    if (id === page.settings.relock_policy) return
                    daemon.typedCall("SetRelockPolicy", [{ "type": "s", "value": id }],
                                     function() { page.statusText = ""; page.reload() },
                                     function() { page.statusText = "Réglage non enregistré" })
                }
            }

            SectionHeader { text: "Base de données" }

            DetailItem {
                label: "Fichier"
                value: {
                    var p = String(page.settings.database || "")
                    return p.split("/").pop()
                }
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
                text: "Choisir un autre fichier…"
                enabled: page.loaded
                onClicked: pageStack.push(kdbxPicker)
            }

            SectionHeader { text: "À propos" }

            DetailItem {
                label: "Version"
                value: page.uiVersion + (page.settings.version && page.settings.version !== page.uiVersion
                                         ? "  (service " + page.settings.version + ")" : "")
            }
            DetailItem { label: "Auteur"; value: "Boris Solodki" }
            DetailItem { label: "Contact"; value: "solboki@solodki.fr" }

            SectionHeader { text: "Crédits" }

            Label {
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryHighlightColor
                textFormat: Text.PlainText
                text: "Service (Rust) :\n"
                      + "• keepass-rs — lecture et écriture des bases KDBX (MIT)\n"
                      + "• zbus — communication D-Bus (MIT)\n"
                      + "• rust-argon2, sha2, rand, zeroize — cryptographie (MIT / Apache-2.0)\n"
                      + "• serde, serde_json, chrono, uuid (MIT / Apache-2.0)\n\n"
                      + "Interface :\n"
                      + "• Sailfish OS, Silica et Maliit — Jolla\n"
                      + "• Qt 5 — The Qt Company (LGPL)\n"
                      + "• FUTO Keyboard pour Sailfish — détection du site et de l'application en cours\n\n"
                      + "Format KeePass : projet KeePass de Dominik Reichl ; compatible KeePassXC et KeePassDX."
                bottomPadding: Theme.paddingLarge
            }
        }
        VerticalScrollDecorator {}
    }
}
