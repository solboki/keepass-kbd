// Champ au style Sailfish : texte, trait de la couleur du thème, libellé en petit dessous.
import QtQuick 2.0
import Sailfish.Silica 1.0

Item {
    id: field
    property string value: ""
    property string label: ""
    property string placeholder: ""
    property bool editing: false
    property bool secret: false
    property bool showSecret: false
    property bool readOnly: false
    signal clicked()

    height: Theme.itemSizeSmall + Theme.paddingSmall

    Item {
        id: textArea
        anchors { left: parent.left; right: eye.visible ? eye.left : parent.right
                  bottom: underline.top; bottomMargin: Theme.paddingSmall }
        height: shown.implicitHeight
        clip: true
        Text {
            id: shown
            x: Math.min(0, parent.width - implicitWidth - cursor.width)
            font.family: field.secret && field.showSecret ? "monospace" : Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            font.letterSpacing: field.secret && !field.showSecret ? 2 : 0
            textFormat: Text.PlainText
            color: field.value.length ? Theme.primaryColor : Theme.secondaryColor
            text: !field.value.length ? field.placeholder
                  : field.secret && !field.showSecret ? Array(field.value.length + 1).join("•")
                  : field.value
        }
        Rectangle {
            id: cursor
            visible: field.editing
            x: field.value.length ? Math.min(shown.x + shown.implicitWidth, parent.width - width) : 0
            width: 2; height: shown.implicitHeight
            color: Theme.highlightColor
            SequentialAnimation on opacity {
                loops: Animation.Infinite
                running: field.editing
                NumberAnimation { to: 0; duration: 500 }
                NumberAnimation { to: 1; duration: 500 }
            }
        }
    }
    IconButton {
        id: eye
        visible: field.secret
        anchors { right: parent.right; verticalCenter: textArea.verticalCenter }
        width: Theme.iconSizeMedium + Theme.paddingSmall; height: width
        icon.source: "image://theme/icon-splus-" + (field.showSecret ? "hide-password" : "show-password")
        onClicked: field.showSecret = !field.showSecret
    }
    Rectangle {
        id: underline
        anchors { left: parent.left; right: parent.right; bottom: labelText.top; bottomMargin: Theme.paddingSmall / 2 }
        height: Math.max(1, Theme.pixelRatio * (field.editing ? 3 : 2))
        color: field.editing ? Theme.highlightColor : Theme.rgba(Theme.highlightColor, field.readOnly ? 0.35 : 0.6)
    }
    Label {
        id: labelText
        anchors { left: parent.left; bottom: parent.bottom }
        font.pixelSize: Theme.fontSizeTiny
        color: field.editing ? Theme.highlightColor : Theme.secondaryHighlightColor
        text: field.label
    }
    MouseArea {
        anchors { left: parent.left; right: eye.visible ? eye.left : parent.right; top: parent.top; bottom: parent.bottom }
        enabled: !field.readOnly
        onClicked: field.clicked()
    }
}
