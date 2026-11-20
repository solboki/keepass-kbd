// Touche « KeePass » du pavé numérique du clavier Jolla (ajoutée par numpad-patch).
// Le clavier Jolla affiche son pavé numérique dans les champs de code et n'y permet pas
// de changer de disposition : cette touche ouvre la disposition KeePass pour y taper
// un code TOTP. Masquée si la disposition KeePass n'est pas activée.
import QtQuick 2.0
import Sailfish.Silica 1.0
import ".."

FunctionKey {
    id: kpxKey

    function keepassIndex() {
        var model = canvas.layoutModel
        for (var i = 0; i < model.count; ++i) {
            var l = model.get(i)
            if (l.enabled && l.layout === "keepass.qml") return i
        }
        return -1
    }
    property int index: (canvas.layoutModel.count, canvas.layoutModel.enabledCount, keepassIndex())

    visible: index >= 0
    enabled: visible
    separator: false
    icon.source: "image://theme/icon-m-keys"

    onClicked: {
        var i = keepassIndex()
        if (i < 0) return
        canvas.switchLayout(i)          // disposition choisie, encore cachée par le pavé
        keyboard.mode = "common"        // puis affichée (jusqu'au prochain champ)
    }
}
