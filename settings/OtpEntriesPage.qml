// Paramètres › Clavier KeePass › Codes à usage unique : choisir une entrée et lui ajouter
// (ou remplacer) son code de double authentification, à partir de la clé secrète, d'un lien
// otpauth://, d'une capture d'écran du QR code ou de l'appareil photo.
// Le service ne transmet ici que le titre et l'identifiant des entrées, jamais leurs secrets.
import QtQuick 2.0
import Sailfish.Silica 1.0
import Nemo.DBus 2.0
import "KpxStrings.js" as S

Page {
    id: entriesPage

    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }

    property var entries: []
    property bool locked: false
    property string query: ""

    function refresh() {
        daemon.typedCall("OtpEntries", [{ "type": "s", "value": query }], function(json) {
            var e = []
            try { e = JSON.parse(json) } catch (err) {}
            entriesPage.entries = e
            entriesPage.locked = false
        }, function() { entriesPage.entries = []; entriesPage.locked = true })
    }

    DBusInterface {
        id: daemon
        bus: DBus.SessionBus
        service: "org.keepasskbd.Daemon"
        path: "/org/keepasskbd/Daemon"
        iface: "org.keepasskbd.Daemon1"
        signalsEnabled: true
        watchServiceStatus: true
        onStatusChanged: entriesPage.refresh()
        function changed() { entriesPage.refresh() }
    }

    Component.onCompleted: refresh()

    SilicaListView {
        id: list
        anchors.fill: parent
        model: entriesPage.entries

        header: Column {
            width: list.width
            PageHeader {
                title: entriesPage.t("One-time codes")
                description: entriesPage.t("Choose the entry to protect")
            }
            SearchField {
                id: search
                width: parent.width
                placeholderText: entriesPage.t("Search")
                // Champ texte : c'est aussi là qu'on ouvre la disposition KeePass pour déverrouiller.
                onTextChanged: { entriesPage.query = text; entriesPage.refresh() }
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }
        }

        delegate: ListItem {
            contentHeight: Theme.itemSizeMedium
            onClicked: pageStack.push(addPage, { entry: modelData })
            Icon {
                id: otpIcon
                anchors { right: parent.right; rightMargin: Theme.horizontalPageMargin; verticalCenter: parent.verticalCenter }
                source: "image://theme/icon-m-timer"
                opacity: modelData.has_totp ? 1.0 : 0.0
                color: Theme.highlightColor
            }
            Column {
                anchors { left: parent.left; leftMargin: Theme.horizontalPageMargin; right: otpIcon.left
                          rightMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                Label {
                    width: parent.width
                    text: modelData.title || entriesPage.t("(untitled)")
                    textFormat: Text.PlainText
                    truncationMode: TruncationMode.Fade
                    color: highlighted ? Theme.highlightColor : Theme.primaryColor
                }
                Label {
                    width: parent.width
                    text: modelData.has_totp ? entriesPage.t("Has a one-time code") + (modelData.username ? "  ·  " + modelData.username : "")
                                             : modelData.username
                    textFormat: Text.PlainText
                    truncationMode: TruncationMode.Fade
                    font.pixelSize: Theme.fontSizeExtraSmall
                    color: highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                }
            }
        }

        ViewPlaceholder {
            enabled: list.count === 0
            text: entriesPage.locked ? entriesPage.t("Database locked") : entriesPage.t("No results")
            hintText: entriesPage.locked
                      ? entriesPage.t("Unlock it with the KeePass layout: tap the search field, then switch to the KeePass layout.")
                      : ""
        }
        VerticalScrollDecorator {}
    }

    // ── Ajout du code d'une entrée ────────────────────────────────────
    Component {
        id: addPage
        Page {
            id: ap
            property var entry: ({})
            property var preview: null
            property bool saving: false
            property string status: ""

            function updatePreview() {
                var input = keyField.text.trim()
                if (input === "") { preview = null; return }
                daemon.typedCall("OtpPreview", [{ "type": "s", "value": input },
                                                 { "type": "s", "value": entry.title || "" },
                                                 { "type": "s", "value": entry.username || "" }],
                                 function(json) {
                                     var r = null
                                     try { r = JSON.parse(json) } catch (e) {}
                                     ap.preview = r
                                 }, function() { ap.preview = { ok: false, error: entriesPage.t("service unavailable") } })
            }
            // Clé lue dans une image ou par l'appareil photo.
            function useScanned(uri) {
                keyField.text = uri
                updatePreview()
            }
            function save() {
                if (!preview || !preview.ok || saving) return
                saving = true
                daemon.typedCall("SetOtp", [{ "type": "s", "value": entry.id },
                                             { "type": "s", "value": keyField.text.trim() },
                                             { "type": "b", "value": entry.has_totp === true }],
                                 function(json) {
                                     ap.saving = false
                                     var r = {}
                                     try { r = JSON.parse(json) } catch (e) {}
                                     if (r.ok) {
                                         keyField.text = ""
                                         pageStack.pop()   // une notification confirme l'enregistrement
                                     } else {
                                         ap.status = r.error || entriesPage.t("save failed")
                                     }
                                 }, function() { ap.saving = false; ap.status = entriesPage.t("service unavailable") })
            }
            Timer {
                interval: 1000
                repeat: true
                running: ap.status === "" && ap.preview !== null && ap.preview.ok === true && Qt.application.active
                onTriggered: ap.updatePreview()
            }
            Timer { id: previewDelay; interval: 400; onTriggered: ap.updatePreview() }

            SilicaFlickable {
                anchors.fill: parent
                contentHeight: addColumn.height + Theme.paddingLarge

                Column {
                    id: addColumn
                    width: parent.width
                    spacing: Theme.paddingMedium

                    PageHeader {
                        title: entriesPage.t("One-time code")
                        description: ap.entry.title || entriesPage.t("(untitled)")
                    }
                    Label {
                        visible: ap.entry.has_totp === true
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        wrapMode: Text.Wrap
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.highlightColor
                        text: entriesPage.t("This entry already has a one-time code: saving replaces it (the previous version stays in the entry history).")
                    }
                    PasswordField {
                        id: keyField
                        width: parent.width
                        label: entriesPage.t("Secret key or otpauth:// link")
                        placeholderText: entriesPage.t("Key shown by the site")
                        inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase | Qt.ImhSensitiveData
                        onTextChanged: { ap.status = ""; previewDelay.restart() }
                        EnterKey.iconSource: "image://theme/icon-m-enter-close"
                        EnterKey.onClicked: { focus = false; ap.updatePreview() }
                    }
                    ButtonLayout {
                        Button {
                            text: entriesPage.t("Paste")
                            onClicked: {
                                var c = String(Clipboard.text || "").trim()
                                if (c === "") ap.status = entriesPage.t("The clipboard is empty")
                                else ap.useScanned(c)
                            }
                        }
                        Button {
                            text: entriesPage.t("Screenshot")
                            onClicked: pageStack.push(imagesPage, { target: ap })
                        }
                        Button {
                            text: entriesPage.t("Camera")
                            onClicked: pageStack.push(Qt.resolvedUrl("OtpCameraPage.qml"), { daemon: daemon, target: ap })
                        }
                    }
                    // Aperçu : émetteur, compte et code actuel, ou l'erreur.
                    Column {
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        spacing: Theme.paddingSmall
                        Label {
                            width: parent.width
                            horizontalAlignment: Text.AlignHCenter
                            wrapMode: Text.Wrap
                            textFormat: Text.PlainText
                            font.pixelSize: Theme.fontSizeSmall
                            color: ap.status !== "" || (ap.preview && !ap.preview.ok) ? Theme.highlightColor : Theme.secondaryColor
                            text: ap.status !== "" ? ap.status
                                  : !ap.preview ? entriesPage.t("Type or paste the key, or choose a screenshot of the QR code")
                                  : !ap.preview.ok ? (ap.preview.error || "")
                                  : [ap.preview.issuer, ap.preview.account].filter(function(x) { return !!x }).join("  ·  ")
                        }
                        Label {
                            visible: ap.preview !== null && ap.preview.ok === true
                            width: parent.width
                            horizontalAlignment: Text.AlignHCenter
                            font.family: "monospace"
                            font.pixelSize: Theme.fontSizeHuge
                            color: Theme.highlightColor
                            text: ap.preview && ap.preview.ok ? String(ap.preview.code).replace(/^(\d{3})(\d{3})$/, "$1 $2") : ""
                        }
                        Label {
                            visible: ap.preview !== null && ap.preview.ok === true
                            width: parent.width
                            horizontalAlignment: Text.AlignHCenter
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.secondaryColor
                            text: ap.preview && ap.preview.ok
                                  ? entriesPage.t("%1 s left · enter this code on the site to finish the activation", ap.preview.remaining)
                                  : ""
                        }
                    }
                    Button {
                        anchors.horizontalCenter: parent.horizontalCenter
                        text: ap.entry.has_totp ? entriesPage.t("Replace the code") : entriesPage.t("Save")
                        enabled: ap.preview !== null && ap.preview.ok === true && !ap.saving
                        onClicked: ap.save()
                    }
                }
                VerticalScrollDecorator {}
            }
        }
    }

    // ── Choix d'une capture d'écran ou d'une photo du QR code ────────
    Component {
        id: imagesPage
        Page {
            id: ip
            property var target: null
            property var images: []
            property string status: ""
            property bool reading: false
            Component.onCompleted: daemon.typedCall("RecentImages", [{ "type": "i", "value": 24 }], function(json) {
                try { ip.images = JSON.parse(json) } catch (e) { ip.images = [] }
            }, function() { ip.status = entriesPage.t("service unavailable") })

            SilicaGridView {
                id: grid
                anchors.fill: parent
                model: ip.images
                cellWidth: width / 3
                cellHeight: cellWidth * 1.5
                header: Column {
                    width: grid.width
                    PageHeader { title: entriesPage.t("Image with the QR code") }
                    Label {
                        visible: ip.status !== "" || ip.reading
                        x: Theme.horizontalPageMargin
                        width: parent.width - 2 * Theme.horizontalPageMargin
                        wrapMode: Text.Wrap
                        color: Theme.highlightColor
                        text: ip.reading ? entriesPage.t("Reading the QR code…") : ip.status
                        bottomPadding: Theme.paddingMedium
                    }
                }
                delegate: BackgroundItem {
                    width: grid.cellWidth
                    height: grid.cellHeight
                    enabled: !ip.reading
                    onClicked: {
                        ip.reading = true
                        ip.status = ""
                        daemon.typedCall("OtpFromImage", [{ "type": "s", "value": modelData.path }], function(json) {
                            ip.reading = false
                            var r = {}
                            try { r = JSON.parse(json) } catch (e) {}
                            if (r.ok) {
                                ip.target.useScanned(r.uri)
                                pageStack.pop()
                            } else {
                                ip.status = r.error || entriesPage.t("no QR code found")
                            }
                        }, function() { ip.reading = false; ip.status = entriesPage.t("service unavailable") })
                    }
                    Image {
                        anchors { fill: parent; margins: Theme.paddingSmall / 2 }
                        source: "file://" + modelData.path
                        sourceSize.width: grid.cellWidth
                        fillMode: Image.PreserveAspectCrop
                        asynchronous: true
                        clip: true
                        opacity: parent.down ? 0.6 : 1.0
                    }
                }
                ViewPlaceholder {
                    enabled: grid.count === 0 && ip.status === ""
                    text: entriesPage.t("No recent screenshot or photo. Take a screenshot of the QR code, then come back here.")
                }
                VerticalScrollDecorator {}
            }
        }
    }
}
