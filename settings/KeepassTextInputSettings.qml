/* Entrée affichée dans Paramètres › Entrée de texte quand la disposition KeePass est active. */
import QtQuick 2.0
import Sailfish.Silica 1.0
import "KpxStrings.js" as S

Column {
    id: entryColumn
    width: parent ? parent.width : 0
    readonly property string lang: S.lang(Qt.locale().name)

    SectionHeader { text: "KeePass" }

    BackgroundItem {
        width: parent.width
        height: Theme.itemSizeMedium
        onClicked: pageStack.animatorPush("/usr/share/jolla-settings/pages/keepass-kbd/main.qml")

        Icon {
            id: icon
            x: Theme.horizontalPageMargin
            anchors.verticalCenter: parent.verticalCenter
            source: "image://theme/icon-m-keys"
            color: parent.highlighted ? Theme.highlightColor : Theme.primaryColor
        }
        Column {
            anchors { left: icon.right; leftMargin: Theme.paddingMedium; right: arrow.left
                      verticalCenter: parent.verticalCenter }
            Label {
                width: parent.width
                text: S.tr(entryColumn.lang, "KeePass Keyboard")
                color: parent.parent.highlighted ? Theme.highlightColor : Theme.primaryColor
                truncationMode: TruncationMode.Fade
            }
            Label {
                width: parent.width
                text: S.tr(entryColumn.lang, "Password database, locking, about")
                font.pixelSize: Theme.fontSizeExtraSmall
                color: parent.parent.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                truncationMode: TruncationMode.Fade
            }
        }
        Icon {
            id: arrow
            anchors { right: parent.right; rightMargin: Theme.horizontalPageMargin; verticalCenter: parent.verticalCenter }
            source: "image://theme/icon-m-right"
            color: parent.highlighted ? Theme.highlightColor : Theme.primaryColor
        }
    }
}
