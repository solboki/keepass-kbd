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

    function openGroups() { pageStack.push(groupPage) }

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
        id: groupPage
        Page {
            id: gp
            property var groups: null
            property string current: ""

            function choose(path) {
                daemon.typedCall("SetNewEntryGroup", [{ "type": "s", "value": path }], function() {
                    page.reload()
                    pageStack.pop()
                }, function() { page.statusText = "Réglage non enregistré" })
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
                    PageHeader { title: "Dossier des nouvelles entrées" }
                    TextField {
                        id: newGroup
                        width: parent.width
                        label: "Nouveau dossier (ex. Internet/Applis)"
                        placeholderText: "Nom d'un nouveau dossier"
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
                        text: "Déverrouillez la base depuis le clavier KeePass pour afficher ses dossiers."
                        bottomPadding: Theme.paddingLarge
                    }
                    SectionHeader { visible: gp.groups !== null; text: "Dossiers de la base" }
                }
                delegate: ListItem {
                    contentHeight: Theme.itemSizeSmall
                    onClicked: gp.choose(modelData)
                    Icon {
                        id: folderIcon
                        x: Theme.horizontalPageMargin + (modelData.split("/").length - 1) * Theme.paddingLarge * (modelData === "" ? 0 : 1)
                        anchors.verticalCenter: parent.verticalCenter
                        source: modelData === "" ? "image://theme/icon-m-home" : "image://theme/icon-m-folder"
                        color: modelData === gp.current ? Theme.highlightColor : Theme.primaryColor
                    }
                    Label {
                        anchors { left: folderIcon.right; leftMargin: Theme.paddingMedium; right: parent.right
                                  rightMargin: Theme.horizontalPageMargin; verticalCenter: parent.verticalCenter }
                        truncationMode: TruncationMode.Fade
                        color: modelData === gp.current ? Theme.highlightColor : Theme.primaryColor
                        text: modelData === "" ? "Racine de la base"
                              : modelData.split("/").pop() + (modelData === "keepass-kbd" ? "  (par défaut)" : "")
                    }
                }
                VerticalScrollDecorator {}
            }
        }
    }

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

            Item { width: 1; height: Theme.paddingLarge }
            ValueButton {
                label: "Dossier des nouvelles entrées"
                value: page.settings.new_entry_group ? page.settings.new_entry_group : "Racine de la base"
                description: "Créé automatiquement au premier enregistrement s'il n'existe pas"
                enabled: page.loaded
                onClicked: page.openGroups()
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
