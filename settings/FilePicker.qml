// Sélecteur de fichier ou de dossier des Paramètres, alimenté par le service (qui lit aussi les
// montages FUSE que l'application Paramètres ne voit pas). kind : "kdbx" (bases), "key"
// (fichiers clés : tout fichier), "dir" (dossier, choisi par « Choisir ce dossier »).
import QtQuick 2.0
import Sailfish.Silica 1.0
import "KpxStrings.js" as S

Page {
    id: picker
    property var daemon: null
    property string kind: "kdbx"
    property string title: ""
    property string startPath: ""
    // Choix « Aucun fichier clé » dans le menu (fichiers clés).
    property bool allowNone: false
    signal chosen(string path)

    property string path: ""
    property var listing: ({})
    property var items: []
    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }

    function open(p) {
        daemon.typedCall("ListFiles", [{ "type": "s", "value": p }, { "type": "s", "value": kind }], function(json) {
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            picker.listing = r
            picker.path = r.path || ""
            var list = []
            if (r.parent && r.path !== "/") list.push({ kind: "up", name: ".." })
            var d = r.dirs || [], f = r.files || []
            for (var i = 0; i < d.length; ++i) list.push({ kind: "dir", name: d[i] })
            for (var j = 0; j < f.length; ++j) list.push({ kind: "file", name: f[j] })
            picker.items = list
        }, function() { picker.listing = { error: true }; picker.items = [] })
    }

    function pick(p) {
        chosen(p)
        pageStack.pop()
    }

    Component.onCompleted: open(startPath)

    SilicaListView {
        anchors.fill: parent
        model: picker.items
        header: Column {
            width: parent.width
            PageHeader {
                title: picker.title
                description: picker.path
            }
            Button {
                visible: picker.kind === "dir"
                anchors.horizontalCenter: parent.horizontalCenter
                text: picker.t("Choose this folder")
                onClicked: picker.pick(picker.path)
            }
            Label {
                visible: !!picker.listing.error || (picker.items.length === 0 && picker.kind !== "dir")
                x: Theme.horizontalPageMargin
                width: parent.width - 2 * Theme.horizontalPageMargin
                wrapMode: Text.Wrap
                color: Theme.highlightColor
                text: picker.listing.error ? picker.t("Cannot open this folder")
                      : picker.kind === "kdbx" ? picker.t("No folder or .kdbx file here") : picker.t("No file here")
                topPadding: Theme.paddingMedium
                bottomPadding: Theme.paddingLarge
            }
        }
        delegate: ListItem {
            contentHeight: Theme.itemSizeSmall
            onClicked: {
                if (modelData.kind === "up") picker.open(picker.listing.parent)
                else if (modelData.kind === "dir") picker.open(picker.path.replace(/\/$/, "") + "/" + modelData.name)
                else picker.pick(picker.path.replace(/\/$/, "") + "/" + modelData.name)
            }
            Icon {
                id: entryIcon
                x: Theme.horizontalPageMargin
                anchors.verticalCenter: parent.verticalCenter
                source: modelData.kind === "file" ? (picker.kind === "kdbx" ? "image://theme/icon-m-keys" : "image://theme/icon-m-document")
                      : modelData.kind === "up" ? "image://theme/icon-m-back" : "image://theme/icon-m-folder"
                color: modelData.kind === "file" ? Theme.highlightColor : Theme.primaryColor
            }
            Label {
                anchors { left: entryIcon.right; leftMargin: Theme.paddingMedium; right: parent.right
                          rightMargin: Theme.horizontalPageMargin; verticalCenter: parent.verticalCenter }
                truncationMode: TruncationMode.Fade
                color: modelData.kind === "file" ? Theme.highlightColor : Theme.primaryColor
                text: modelData.kind === "up" ? picker.t("Parent folder") : modelData.name
            }
        }
        PullDownMenu {
            MenuItem {
                visible: picker.allowNone
                text: picker.t("No key file")
                onClicked: picker.pick("")
            }
            MenuItem {
                text: picker.t("Home folder")
                onClicked: picker.open(picker.listing.home || "")
            }
        }
        VerticalScrollDecorator {}
    }
}
