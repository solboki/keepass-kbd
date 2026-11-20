// Mini-clavier interne : ce qui y est tapé reste dans la disposition KeePass
// (mot de passe maître, recherche, champs d'une nouvelle entrée) et n'est
// jamais envoyé à l'application au premier plan.
import QtQuick 2.0
import Sailfish.Silica 1.0

Column {
    id: kb
    property real rowHeight: Theme.itemSizeExtraSmall
    property int page: 0          // 0 lettres, 1 chiffres/symboles, 2 symboles/accents
    property bool shifted: false
    property bool capsLock: false
    property string enterLabel: "↵"
    signal typed(string text)
    signal backspace()
    signal accepted()

    readonly property var pages: [
        [ "azertyuiop", "qsdfghjklm", "⇧wxcvbn'⌫", "⌨, .↵" ],
        [ "1234567890", "@#$%&*-+()", "⇧!\"':;/?⌫", "⌨, .↵" ],
        [ "~`|^_=[]{}", "éèêàçùôîï€", "⇧<>\\°£µ§⌫", "⌨, .↵" ]
    ]

    function label(ch) {
        if (ch === " ") return "espace"
        if (ch === "↵") return enterLabel
        if (ch === "⌨") return page === 0 ? "?123" : "ABC"
        if (ch === "⇧") return page === 0 ? (capsLock ? "⇪" : "⇧") : (page === 1 ? "#+=" : "123")
        if (page === 0 && shifted) return ch.toUpperCase()
        return ch
    }

    function press(ch) {
        if (ch === "⌫") { backspace(); return }
        if (ch === "↵") { accepted(); return }
        if (ch === "⌨") { page = page === 0 ? 1 : 0; shifted = false; return }
        if (ch === "⇧") {
            if (page === 0) {
                if (capsLock) { capsLock = false; shifted = false }
                else if (shifted) { capsLock = true }
                else shifted = true
            } else {
                page = page === 1 ? 2 : 1
            }
            return
        }
        typed(page === 0 && shifted ? ch.toUpperCase() : ch)
        if (shifted && !capsLock) shifted = false
    }

    Repeater {
        model: 4
        Row {
            id: row
            property string keys: kb.pages[kb.page][index]
            width: kb.width
            height: kb.rowHeight
            Repeater {
                model: row.keys.length
                Item {
                    property string ch: row.keys.charAt(index)
                    readonly property bool wide: ch === " "
                    readonly property bool func: "⇧⌫⌨↵".indexOf(ch) >= 0
                    width: wide ? kb.width * 0.4
                                : (row.keys.length === 5 ? kb.width * 0.15 : kb.width / row.keys.length)
                    height: row.height
                    Rectangle {
                        anchors.fill: parent
                        anchors.margins: 2
                        radius: Theme.paddingSmall / 2
                        color: key.pressed ? Theme.rgba(Theme.highlightBackgroundColor, 0.6)
                                           : Theme.rgba(Theme.primaryColor, func ? 0.18 : 0.10)
                        Label {
                            anchors.centerIn: parent
                            text: kb.label(ch)
                            font.pixelSize: ch === " " || ch === "⌨" || (ch === "↵" && kb.enterLabel.length > 2) ? Theme.fontSizeExtraSmall
                                                                    : Theme.fontSizeMedium
                            color: key.pressed || (ch === "⇧" && kb.shifted) ? Theme.highlightColor
                                                                            : Theme.primaryColor
                        }
                    }
                    MouseArea {
                        id: key
                        anchors.fill: parent
                        preventStealing: true
                        onClicked: kb.press(ch)
                        onPressAndHold: if (ch === "⌫") repeat.start()
                        onReleased: repeat.stop()
                        onCanceled: repeat.stop()
                        Timer { id: repeat; interval: 80; repeat: true; onTriggered: kb.backspace() }
                    }
                }
            }
        }
    }
}
