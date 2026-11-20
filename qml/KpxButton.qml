// Bouton de la disposition KeePass : icône du thème Sailfish, texte, ou les deux.
import QtQuick 2.0
import Sailfish.Silica 1.0

Rectangle {
    id: button
    property alias text: label.text
    property string iconSource: ""
    property bool highlighted: false
    property bool active: true
    property bool round: false
    property bool flat: false
    property real fontSize: Theme.fontSizeSmall
    signal clicked()

    readonly property bool down: mouse.pressed && mouse.containsMouse

    radius: round ? Math.min(width, height) / 2 : Theme.paddingMedium
    opacity: active ? 1.0 : 0.35
    color: down ? Theme.rgba(Theme.highlightBackgroundColor, 0.55)
         : highlighted ? Theme.rgba(Theme.highlightBackgroundColor, 0.35)
         : flat ? "transparent"
         : Theme.rgba(Theme.primaryColor, 0.09)
    Behavior on color { ColorAnimation { duration: 80 } }

    Row {
        anchors.centerIn: parent
        spacing: Theme.paddingSmall
        Icon {
            visible: button.iconSource !== ""
            anchors.verticalCenter: parent.verticalCenter
            source: button.iconSource
            width: Math.min(Theme.iconSizeMedium, button.height * 0.7)
            height: width
            color: button.down || button.highlighted ? Theme.highlightColor : Theme.primaryColor
        }
        Label {
            id: label
            visible: text !== ""
            anchors.verticalCenter: parent.verticalCenter
            width: Math.min(implicitWidth,
                            button.width - (button.iconSource !== "" ? Theme.iconSizeMedium : 0) - 2 * Theme.paddingSmall)
            truncationMode: TruncationMode.Fade
            font.pixelSize: button.fontSize
            color: button.down || button.highlighted ? Theme.highlightColor : Theme.primaryColor
        }
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        enabled: button.active
        preventStealing: true
        onClicked: button.clicked()
    }
}
