// Champ au style Sailfish : texte, trait de la couleur du thème, libellé en petit dessous.
// Le curseur se place à l'endroit touché (glisser pour l'ajuster) ; la saisie vient du mini-clavier.
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
    property bool error: false
    property int cursorPosition: value.length
    signal clicked()
    signal cursorRequested(int position)
    signal secretToggled()

    height: Theme.itemSizeSmall + Theme.paddingSmall

    TextInput {
        id: input
        anchors { left: parent.left; right: eye.visible ? eye.left : parent.right
                  bottom: underline.top; bottomMargin: Theme.paddingSmall }
        readOnly: true
        activeFocusOnPress: false
        selectByMouse: false
        autoScroll: true
        clip: true
        text: field.value
        echoMode: field.secret && !field.showSecret ? TextInput.Password : TextInput.Normal
        passwordCharacter: "•"
        font.family: field.secret && field.showSecret ? "monospace" : Theme.fontFamily
        font.pixelSize: Theme.fontSizeMedium
        color: Theme.primaryColor
        cursorVisible: field.editing
        cursorPosition: Math.max(0, Math.min(field.cursorPosition, field.value.length))
        cursorDelegate: Rectangle {
            width: 2
            color: Theme.highlightColor
            visible: field.editing
            SequentialAnimation on opacity {
                loops: Animation.Infinite
                running: field.editing
                NumberAnimation { to: 0; duration: 500 }
                NumberAnimation { to: 1; duration: 500 }
            }
        }
        Text {
            visible: field.value.length === 0
            anchors.verticalCenter: parent.verticalCenter
            font.family: Theme.fontFamily
            font.pixelSize: Theme.fontSizeMedium
            color: Theme.secondaryColor
            text: field.placeholder
        }
    }
    IconButton {
        id: eye
        visible: field.secret
        anchors { right: parent.right; verticalCenter: input.verticalCenter }
        width: Theme.iconSizeMedium + Theme.paddingSmall; height: width
        icon.source: "image://theme/icon-splus-" + (field.showSecret ? "hide-password" : "show-password")
        onClicked: field.secretToggled()
    }
    Rectangle {
        id: underline
        anchors { left: parent.left; right: parent.right; bottom: labelText.top; bottomMargin: Theme.paddingSmall / 2 }
        height: Math.max(1, Theme.pixelRatio * (field.editing ? 3 : 2))
        color: field.error ? Theme.errorColor
             : field.editing ? Theme.highlightColor
             : Theme.rgba(Theme.highlightColor, field.readOnly ? 0.35 : 0.6)
    }
    Label {
        id: labelText
        anchors { left: parent.left; bottom: parent.bottom }
        font.pixelSize: Theme.fontSizeTiny
        color: field.error ? Theme.errorColor : field.editing ? Theme.highlightColor : Theme.secondaryHighlightColor
        text: field.label
    }
    MouseArea {
        anchors { left: parent.left; right: eye.visible ? eye.left : parent.right; top: parent.top; bottom: parent.bottom }
        enabled: !field.readOnly
        preventStealing: true
        function place(mouse) {
            var p = mapToItem(input, mouse.x, mouse.y)
            field.cursorRequested(input.positionAt(p.x, input.height / 2))
        }
        onPressed: place(mouse)
        onPositionChanged: place(mouse)
        onClicked: field.clicked()
    }
}
