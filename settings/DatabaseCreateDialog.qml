// Paramètres › Clavier KeePass › Créer une nouvelle base : base des mots de passe
// (target "main") ou base des codes à usage unique ("otp"), avec son fichier clé éventuel.
// La page principale fait la création à l'acceptation (voir createDatabase dans main.qml) :
// cette boîte se ferme aussitôt et on revient sur la page principale.
import QtQuick 2.0
import Sailfish.Silica 1.0
import "KpxStrings.js" as S

Dialog {
    id: dlg
    property var daemon: null
    property var settings: ({})
    property string target: "otp"

    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }
    function dirOf(p) { return String(p || "").replace(/\/[^\/]*$/, "") }
    readonly property string documents: (settings.home || "/home/defaultuser") + "/Documents"

    property string folder: target === "otp" ? (dirOf(settings.database) || documents) : documents
    // 0 : mot de passe, 1 : mot de passe et fichier clé, 2 : fichier clé seul (base des codes)
    property int protection: 0
    property bool newKey: true
    property string existingKey: ""
    property string keyFolder: documents
    readonly property bool usesPassword: protection !== 2
    readonly property bool usesKey: protection !== 0
    readonly property bool keyOnly: protection === 2
    readonly property string fileName: {
        var n = nameField.text.trim()
        return n === "" ? "" : (/\.kdbx$/i.test(n) ? n : n + ".kdbx")
    }
    readonly property string dbPath: folder + "/" + fileName
    readonly property string password: usesPassword ? pw1.text : ""
    readonly property string keyPath: !usesKey ? ""
                                      : newKey ? keyFolder + "/" + fileName.replace(/\.kdbx$/i, "") + ".keyx"
                                      : existingKey

    canAccept: fileName !== ""
               && (!usesPassword || (pw1.text.length > 0 && pw1.text === pw2.text))
               && (!usesKey || keyPath !== "")

    SilicaFlickable {
        anchors.fill: parent
        contentHeight: form.height + Theme.paddingLarge
        Column {
            id: form
            width: parent.width
            spacing: Theme.paddingSmall
            DialogHeader {
                acceptText: dlg.t("Create")
                title: dlg.target === "otp" ? dlg.t("New one-time codes database") : dlg.t("New password database")
            }
            TextField {
                id: nameField
                width: parent.width
                label: dlg.t("File name")
                text: dlg.target === "otp" ? "codes-otp.kdbx" : "keepass.kdbx"
                inputMethodHints: Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }
            ValueButton {
                label: dlg.t("Folder")
                value: dlg.folder
                onClicked: {
                    var p = pageStack.push(Qt.resolvedUrl("FilePicker.qml"),
                                           { daemon: dlg.daemon, kind: "dir", startPath: dlg.folder, title: dlg.t("Folder") })
                    p.chosen.connect(function(path) { dlg.folder = path })
                }
            }
            ComboBox {
                label: dlg.t("Protection")
                currentIndex: dlg.protection
                menu: ContextMenu {
                    MenuItem { text: dlg.t("Password") }
                    MenuItem { text: dlg.t("Password and key file") }
                    MenuItem { visible: dlg.target === "otp"; text: dlg.t("Key file only") }
                }
                onCurrentIndexChanged: dlg.protection = currentIndex
                description: dlg.protection === 2
                             ? dlg.t("Nothing to type: anyone who can read the key file can open the database. Keep it outside synchronised folders.")
                             : ""
            }
            PasswordField {
                id: pw1
                visible: dlg.usesPassword
                width: parent.width
                label: dlg.t("Password")
                EnterKey.iconSource: "image://theme/icon-m-enter-next"
                EnterKey.onClicked: pw2.focus = true
            }
            PasswordField {
                id: pw2
                visible: dlg.usesPassword
                width: parent.width
                label: pw2.text.length > 0 && pw2.text !== pw1.text ? dlg.t("The passwords differ")
                                                                    : dlg.t("Confirm the password")
                errorHighlight: pw2.text.length > 0 && pw2.text !== pw1.text
                EnterKey.iconSource: "image://theme/icon-m-enter-close"
                EnterKey.onClicked: focus = false
            }
            ComboBox {
                visible: dlg.usesKey
                label: dlg.t("Key file")
                currentIndex: dlg.newKey ? 0 : 1
                menu: ContextMenu {
                    MenuItem { text: dlg.t("Create a new key file") }
                    MenuItem { text: dlg.t("Use an existing key file…") }
                }
                onCurrentIndexChanged: {
                    dlg.newKey = currentIndex === 0
                    if (!dlg.newKey && dlg.existingKey === "") {
                        var p = pageStack.push(Qt.resolvedUrl("FilePicker.qml"),
                                               { daemon: dlg.daemon, kind: "key", title: dlg.t("Key file") })
                        p.chosen.connect(function(path) { dlg.existingKey = path })
                    }
                }
            }
            ValueButton {
                visible: dlg.usesKey && dlg.newKey
                label: dlg.t("Key file folder")
                value: dlg.keyFolder
                onClicked: {
                    var p = pageStack.push(Qt.resolvedUrl("FilePicker.qml"),
                                           { daemon: dlg.daemon, kind: "dir", startPath: dlg.keyFolder,
                                             title: dlg.t("Key file folder") })
                    p.chosen.connect(function(path) { dlg.keyFolder = path })
                }
            }
            Label {
                visible: dlg.usesKey
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.WrapAnywhere
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.secondaryColor
                text: dlg.keyPath
            }
            Label {
                visible: dlg.usesKey
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                font.pixelSize: Theme.fontSizeExtraSmall
                color: Theme.highlightColor
                text: dlg.t("Keep a copy of the key file elsewhere (computer, USB stick) and do not put it in the same synchronised folder as the database.")
            }
        }
        VerticalScrollDecorator {}
    }
}
