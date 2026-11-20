// Touche d'effacement (caractère à gauche du curseur dans l'application), répétée en appui long.
import QtQuick 2.0
import Sailfish.Silica 1.0

KpxButton {
    id: key
    signal erase()
    iconSource: "image://theme/icon-m-backspace"
    onClicked: if (!repeater.fired) key.erase()

    Timer {
        id: delay
        interval: 450
        running: key.down
        onTriggered: { repeater.fired = true; repeater.start() }
    }
    Timer {
        id: repeater
        property bool fired: false
        interval: 70
        repeat: true
        running: false
        onTriggered: key.down ? key.erase() : stop()
    }
    onDownChanged: if (down) repeater.fired = false; else repeater.stop()
}
