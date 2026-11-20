// Disposition clavier « KeePass » : saisie d'identifiants depuis la base .kdbx
// via le service keepass-kbd (D-Bus de session org.keepasskbd.Daemon).
// Version @VERSION@
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.meego.maliitquick 1.0
import Nemo.DBus 2.0
import ".."

KeyboardLayout {
    id: root
    splitSupported: false
    useTopItem: false
    capsLockSupported: false

    // État : "locked", "list", "generate", "save", "missing", "offline"
    property string mode: "offline"
    property string statusMessage: ""
    property string busyText: ""
    property bool typing: false              // mini-clavier visible (recherche, enregistrement)
    property string masterPassword: ""
    property bool showMaster: false
    property string query: ""
    property var entries: []
    property var suggestions: []
    property string origin: ""               // site ou application au premier plan
    property var listModel: []
    property var selected: null              // entrée choisie {id,title,username,url}
    property string generated: ""
    property int genLength: 20
    property bool genLower: true
    property bool genUpper: true
    property bool genDigits: true
    property bool genSymbols: true
    property string saveTitle: ""
    property string saveUser: ""
    property string saveUrl: ""
    property string editing: ""              // "master", "query", "title", "user", "url"

    readonly property int keyClick: typeof Maliit !== "undefined" ? Maliit.KeyClick : 0
    readonly property real unit: keyHeight > 0 ? keyHeight : Theme.itemSizeSmall
    readonly property bool passwordField: MInputMethodQuick.hiddenText
                                          || !!MInputMethodQuick.extensions.sensitiveInput
    readonly property string originLabel: origin.indexOf("app://") === 0 ? origin.substring(6)
                                          : origin.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").split("/")[0]

    function clearSecrets() {
        masterPassword = ""
        showMaster = false
        generated = ""
        saveTitle = ""; saveUser = ""; saveUrl = ""
        autofill.stop()
    }

    function commit(text) {
        if (text && text.length > 0)
            MInputMethodQuick.sendCommit(text)
    }

    // Dernière disposition utilisée avant KeePass (FUTO en général).
    property int previousIndex: -1

    function backToKeyboard() {
        clearSecrets()
        typing = false
        var model = canvas.layoutModel
        if (previousIndex >= 0 && previousIndex < model.count && previousIndex !== layoutIndex) {
            var p = model.get(previousIndex)
            if (p.enabled && p.layout !== "keepass.qml") {
                canvas.switchLayout(previousIndex)
                return
            }
        }
        for (var i = 0; i < model.count; ++i) {
            var l = model.get(i)
            if (l.enabled && l.layout !== "keepass.qml" && l.type !== "emojis") {
                canvas.switchLayout(i)
                return
            }
        }
        if (typeof canvas.switchToPreviousCharacterLayout === "function")
            canvas.switchToPreviousCharacterLayout()
    }

    function refreshStatus() {
        daemon.typedCall("Status", [], function(json) {
            var s = {}
            try { s = JSON.parse(json) } catch (e) {}
            statusMessage = s.message || ""
            if (s.state === "unlocked") {
                if (mode === "locked" || mode === "offline" || mode === "missing") {
                    mode = "list"; typing = false; editing = ""
                }
                refreshOrigin()
                search()
            } else if (s.state === "missing") {
                mode = "missing"
            } else {
                mode = "locked"; editing = "master"; typing = false
                entries = []; suggestions = []; selected = null; buildModel()
                autofill.stop()
            }
        }, function(err) { mode = "offline" })
    }

    // ── Origine : site web ou application au premier plan ─────────────
    function normId(value) {
        value = String(value || "").trim().toLowerCase()
        if (value.indexOf("/") >= 0) value = value.split("/")[0]
        if (value.indexOf(":") >= 0) value = value.split(":")[0]
        return /^[a-z0-9][a-z0-9._-]{1,200}$/.test(value) && !/^(none|null|undefined|unknown|0)$/.test(value)
               ? value : ""
    }

    function originFromApp(id, callback) {
        if (id === "sailfish-browser" || id === "org.sailfishos.browser" || id === "jolla-browser") {
            futo.typedCall("NativeBrowserCredentialContext", [], function(json) {
                var c = {}
                try { c = JSON.parse(String(json)) } catch (e) {}
                callback(c.available ? String(c.origin || "") : "")
            }, function() { callback("") })
        } else if (/firefox|fennec|chrome|chromium|browser|brave|opera|vivaldi|edge|duckduckgo/.test(id)) {
            futo.typedCall("CurrentAndroidBrowserOrigin", [{ "type": "s", "value": id }],
                           function(o) { callback(String(o || "")) }, function() { callback("") })
        } else {
            callback("app://" + id)
        }
    }

    function resolveOrigin(callback) {
        compositor.typedCall("privateTopmostWindowPolicyApplicationId", [], function(appId) {
            var id = normId(appId)
            if (id !== "" && !/^[0-9a-f]+$/.test(id)) {
                originFromApp(id, callback)
                return
            }
            compositor.typedCall("privateTopmostWindowProcessId", [], function(pid) {
                futo.typedCall("CredentialProcessApplication", [{ "type": "i", "value": Number(pid) }], function(a) {
                    a = normId(a)
                    if (a !== "") { originFromApp(a, callback); return }
                    futo.typedCall("CurrentAndroidApplication", [], function(p) {
                        p = normId(p)
                        if (p !== "") originFromApp(p, callback); else callback("")
                    }, function() { callback("") })
                }, function() { callback("") })
            }, function() { callback("") })
        }, function() { callback("") })
    }

    function refreshOrigin() {
        resolveOrigin(function(o) {
            origin = o
            if (o === "") { suggestions = []; buildModel(); return }
            daemon.typedCall("Suggest", [{ "type": "s", "value": o }], function(json) {
                try { suggestions = JSON.parse(json) } catch (e) { suggestions = [] }
                // Présélection de la meilleure suggestion : les boutons du bas sont prêts.
                if (suggestions.length > 0 && (!selected || query === "")) selected = suggestions[0]
                buildModel()
            }, function() { suggestions = []; buildModel() })
        })
    }

    function buildModel() {
        var items = []
        if (query === "" && suggestions.length > 0) {
            var ids = {}
            items.push({ kind: "header", text: "Suggestions pour " + originLabel })
            for (var i = 0; i < suggestions.length; ++i) {
                items.push({ kind: "entry", entry: suggestions[i], suggested: true })
                ids[suggestions[i].id] = true
            }
            items.push({ kind: "header", text: "Toutes les entrées" })
            for (var j = 0; j < entries.length; ++j)
                if (!ids[entries[j].id]) items.push({ kind: "entry", entry: entries[j], suggested: false })
        } else {
            for (var k = 0; k < entries.length; ++k)
                items.push({ kind: "entry", entry: entries[k], suggested: false })
        }
        listModel = items
    }

    function search() {
        daemon.typedCall("Search", [{ "type": "s", "value": query }, { "type": "i", "value": 60 }],
                         function(json) {
                             try { entries = JSON.parse(json) } catch (e) { entries = [] }
                             buildModel()
                         }, function() { refreshStatus() })
    }

    function unlock() {
        if (masterPassword.length === 0 || busyText !== "") return
        showMaster = false
        busyText = "Déverrouillage…"
        var pw = masterPassword
        daemon.typedCall("Unlock", [{ "type": "s", "value": pw }], function(json) {
            busyText = ""
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            if (r.ok) {
                masterPassword = ""
                statusMessage = ""
                query = ""
                mode = "list"; typing = false; editing = ""
                refreshOrigin()
                search()
            } else {
                // La saisie est conservée : l'œil permet de la vérifier et de la corriger.
                statusMessage = r.error || "échec du déverrouillage"
            }
        }, function(err) { busyText = ""; statusMessage = "service indisponible" })
        pw = ""
    }

    function insertField(field, callback) {
        if (!selected) return
        daemon.typedCall("GetField", [{ "type": "s", "value": selected.id }, { "type": "s", "value": field }],
                         function(value) { commit(value); if (callback) callback() },
                         function() { refreshStatus() })
    }

    // Remplissage automatique : identifiant, passage au champ suivant, mot de passe.
    function chooseEntry(entry) {
        selected = entry
        typing = false
        if (passwordField) {
            insertField("password")
            return
        }
        insertField("username", function() {
            var icon = String(MInputMethodQuick.actionKeyOverride.icon || "")
            if (icon.indexOf("next") >= 0)
                MInputMethodQuick.sendKey(Qt.Key_Return, 0, "\r", root.keyClick)
            else
                MInputMethodQuick.sendKey(Qt.Key_Tab, 0, "", root.keyClick)
            autofill.attempts = 0
            autofill.start()
        })
    }

    Timer {
        id: autofill
        interval: 120
        repeat: true
        property int attempts: 0
        onTriggered: {
            if (root.passwordField) {
                stop()
                root.insertField("password")
                root.statusMessage = "identifiant et mot de passe insérés"
            } else if (++attempts > 10) {
                stop()
                root.statusMessage = "touchez le champ mot de passe puis la clé ci-dessous"
            }
        }
    }

    // Efface le caractère à gauche du curseur dans le champ de l'application.
    function appBackspace() {
        MInputMethodQuick.sendKey(Qt.Key_Backspace, 0, "\b", root.keyClick)
    }

    function generate() {
        var classes = (genLower ? "l" : "") + (genUpper ? "u" : "") + (genDigits ? "d" : "") + (genSymbols ? "s" : "")
        daemon.typedCall("Generate", [{ "type": "u", "value": genLength }, { "type": "s", "value": classes }],
                         function(p) { generated = p; statusMessage = "" },
                         function() { statusMessage = "choisissez au moins un type de caractères" })
    }

    // Mot de passe généré avec chiffres et symboles colorés.
    function styledPassword(p) {
        var out = ""
        for (var i = 0; i < p.length; ++i) {
            var c = p.charAt(i)
            var esc = c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : c === "\"" ? "&quot;" : c
            if (/[0-9]/.test(c)) out += "<font color='" + Theme.highlightColor + "'>" + esc + "</font>"
            else if (/[a-zA-Z]/.test(c)) out += esc
            else out += "<font color='" + Theme.secondaryHighlightColor + "'>" + esc + "</font>"
        }
        return out
    }

    function saveEntry() {
        if (generated.length === 0 || saveTitle.trim().length === 0) {
            statusMessage = "le titre est obligatoire"
            return
        }
        busyText = "Enregistrement dans la base…"
        daemon.typedCall("AddEntry", [
                             { "type": "s", "value": saveTitle.trim() },
                             { "type": "s", "value": saveUser },
                             { "type": "s", "value": generated },
                             { "type": "s", "value": saveUrl.trim() }],
                         function(json) {
                             busyText = ""
                             var r = {}
                             try { r = JSON.parse(json) } catch (e) {}
                             if (r.ok) {
                                 clearSecrets()
                                 mode = "list"; typing = false; editing = ""
                                 statusMessage = "entrée enregistrée"
                                 refreshOrigin()
                                 search()
                             } else {
                                 statusMessage = r.error || "échec de l'enregistrement"
                             }
                         }, function() { busyText = ""; statusMessage = "service indisponible" })
    }

    function editText(t) {
        if (editing === "master") { masterPassword += t; statusMessage = "" }
        else if (editing === "query") { query += t; search() }
        else if (editing === "title") saveTitle += t
        else if (editing === "user") saveUser += t
        else if (editing === "url") saveUrl += t
    }

    function editBackspace() {
        if (editing === "master") masterPassword = masterPassword.slice(0, -1)
        else if (editing === "query") { query = query.slice(0, -1); search() }
        else if (editing === "title") saveTitle = saveTitle.slice(0, -1)
        else if (editing === "user") saveUser = saveUser.slice(0, -1)
        else if (editing === "url") saveUrl = saveUrl.slice(0, -1)
    }

    function editAccept() {
        if (editing === "master") unlock()
        else if (editing === "query") typing = false
        else if (editing === "title") startEditing("user")
        else if (editing === "user") startEditing("url")
        else if (editing === "url") { typing = false; saveEntry() }
    }

    function startEditing(key) {
        // Toucher le champ déjà en cours d'édition referme le mini-clavier (bouton visible).
        if (typing && editing === key) { typing = false; return }
        editing = key
        typing = true
        ensureFieldTimer.restart()
    }
    Timer {
        id: ensureFieldTimer
        interval: 50
        onTriggered: saveForm.ensureVisible(root.editing === "title" ? titleField
                                            : root.editing === "user" ? userField : urlField)
    }

    // ── Préremplissage du formulaire d'enregistrement ─────────────────
    // Identifiant tapé sur la page : mémorisé par FUTO (lastCredentialUsername),
    // sinon par le suivi de secours ci-dessous. Uniquement en mémoire vive.
    property string trackedUsername: ""

    function originKey(o) {
        o = String(o || "").trim().toLowerCase()
        if (o.indexOf("app://") === 0) return o.replace(/\/+$/, "")
        return o.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").split(/[\/?#:]/)[0]
    }

    function sameSite(a, b) {
        var ka = originKey(a), kb = originKey(b)
        if (ka === "" || kb === "") return true
        if (ka === kb) return true
        // Sous-domaines d'un même site (compte.laposte.fr / laposte.fr)
        return ka.length > kb.length ? ka.slice(-kb.length - 1) === "." + kb : kb.slice(-ka.length - 1) === "." + ka
    }

    function pageUsername() {
        var handlers = canvas.layoutModel ? canvas.layoutModel.inputHandlers : null
        var futoHandler = handlers ? handlers["FutoInputHandler.qml"] : null
        if (futoHandler && futoHandler.lastCredentialUsername
                && sameSite(futoHandler.lastCredentialUsernameOrigin, origin))
            return String(futoHandler.lastCredentialUsername)
        return trackedUsername
    }

    function openSaveForm() {
        statusMessage = ""
        mode = "save"
        if (saveUrl === "" && origin !== "") saveUrl = origin
        if (saveUser === "") saveUser = pageUsername()
        typing = false; editing = ""
        if (saveTitle === "" && origin !== "") {
            daemon.typedCall("SuggestTitle", [{ "type": "s", "value": origin }], function(t) {
                if (root.saveTitle === "") root.saveTitle = String(t || "")
                if (root.saveTitle === "") root.startEditing("title")
            }, function() { root.startEditing("title") })
        } else if (saveTitle === "") {
            startEditing("title")
        }
    }

    // Couleur d'avatar stable dérivée du titre.
    function avatarColor(text) {
        var h = 0
        for (var i = 0; i < text.length; ++i) h = (h * 31 + text.charCodeAt(i)) % 360
        return Qt.hsla(h / 360, 0.45, 0.45, 1)
    }

    DBusInterface {
        id: daemon
        bus: DBus.SessionBus
        service: "org.keepasskbd.Daemon"
        path: "/org/keepasskbd/Daemon"
        iface: "org.keepasskbd.Daemon1"
        signalsEnabled: true
        watchServiceStatus: true
        onStatusChanged: root.refreshStatus()
        function changed() { root.refreshStatus() }
    }
    DBusInterface {
        id: settingsUi
        bus: DBus.SessionBus
        service: "com.jolla.settings"
        path: "/com/jolla/settings/ui"
        iface: "com.jolla.settings.ui"
    }
    DBusInterface {
        id: compositor
        bus: DBus.SessionBus
        service: "org.nemomobile.lipstick"
        path: "/"
        iface: "org.nemomobile.compositor"
    }
    DBusInterface {
        id: futo
        bus: DBus.SessionBus
        service: "org.hb.FutoKeyboard1"
        path: "/org/hb/FutoKeyboard1"
        iface: "org.hb.FutoKeyboard1"
    }

    // Rafraîchir quand la disposition devient active ; effacer les secrets quand elle est quittée.
    Connections {
        target: canvas
        onActiveIndexChanged: {
            if (canvas.activeIndex === root.layoutIndex) {
                root.refreshStatus()
            } else {
                root.previousIndex = canvas.activeIndex
                root.clearSecrets()
            }
        }
    }
    Connections {
        target: MInputMethodQuick
        onSurroundingTextChanged: {
            if (root.passwordField || canvas.activeIndex === root.layoutIndex) return
            var t = String(MInputMethodQuick.surroundingText || "").trim()
            if (t.length >= 3 && t.length <= 120 && !/\s/.test(t) && !/^[a-z]+:\/\//i.test(t))
                root.trackedUsername = t
        }
        onActiveChanged: {
            if (!MInputMethodQuick.active) {
                hideTimer.restart()
            } else {
                hideTimer.stop()
                if (canvas.activeIndex === root.layoutIndex) root.refreshStatus()
            }
        }
    }

    // Clavier fermé : après un court délai (le passage d'un champ à l'autre peut
    // masquer brièvement le clavier), effacer les secrets et revenir à la disposition précédente.
    Timer {
        id: hideTimer
        interval: 700
        onTriggered: {
            if (MInputMethodQuick.active) return
            root.clearSecrets()
            root.trackedUsername = ""
            root.typing = false
            if (canvas.activeIndex === root.layoutIndex) root.backToKeyboard()
        }
    }
    Component.onCompleted: {
        if (canvas.activeIndex !== layoutIndex) previousIndex = canvas.activeIndex
        refreshStatus()
    }

    Item {
        id: surface
        width: root.width
        height: root.unit * 6

        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: Theme.rgba(Theme.highlightBackgroundColor, 0.10) }
                GradientStop { position: 1.0; color: Theme.rgba(Theme.primaryColor, 0.03) }
            }
        }

        // ── Barre du haut ─────────────────────────────────────────────
        Item {
            id: header
            width: parent.width
            height: root.unit * 0.95

            KpxButton {
                id: abcButton
                anchors { left: parent.left; leftMargin: Theme.paddingSmall; verticalCenter: parent.verticalCenter }
                width: root.unit * 1.15; height: root.unit * 0.8
                iconSource: "image://theme/icon-m-keyboard"
                flat: true
                onClicked: root.backToKeyboard()
            }
            Row {
                anchors { left: abcButton.right; leftMargin: Theme.paddingMedium; right: rightButtons.left
                          rightMargin: Theme.paddingSmall; verticalCenter: parent.verticalCenter }
                spacing: Theme.paddingMedium
                Icon {
                    anchors.verticalCenter: parent.verticalCenter
                    source: root.mode === "locked" ? "image://theme/icon-m-device-lock" : "image://theme/icon-m-keys"
                    width: Theme.iconSizeSmallPlus; height: width
                    color: Theme.highlightColor
                }
                Column {
                    anchors.verticalCenter: parent.verticalCenter
                    width: parent.width - Theme.iconSizeSmallPlus - Theme.paddingMedium
                    Label {
                        width: parent.width
                        truncationMode: TruncationMode.Fade
                        font.pixelSize: Theme.fontSizeSmall
                        color: Theme.highlightColor
                        text: root.mode === "generate" ? "Nouveau mot de passe"
                              : root.mode === "save" ? "Enregistrer dans KeePass"
                              : "KeePass"
                    }
                    Label {
                        width: parent.width
                        truncationMode: TruncationMode.Fade
                        font.pixelSize: Theme.fontSizeExtraSmall
                        color: root.busyText !== "" || root.statusMessage !== "" ? Theme.primaryColor
                                                                               : Theme.secondaryColor
                        text: root.busyText !== "" ? root.busyText
                              : root.statusMessage !== "" ? root.statusMessage
                              : root.mode === "locked" ? "Base verrouillée"
                              : root.mode === "missing" ? "Base introuvable"
                              : root.mode === "offline" ? "Service arrêté"
                              : root.origin !== "" ? root.originLabel
                              : (root.entries.length + " entrées")
                    }
                }
            }
            Row {
                id: rightButtons
                anchors { right: parent.right; rightMargin: Theme.paddingSmall; verticalCenter: parent.verticalCenter }
                spacing: Theme.paddingSmall
                // L'engrenage reste le dernier élément : toujours aligné sur le bord droit.
                KpxButton {
                    visible: root.mode === "list" || root.mode === "generate" || root.mode === "save"
                    width: root.unit * 1.05; height: root.unit * 0.8
                    flat: true
                    iconSource: root.mode === "list" ? "image://theme/icon-m-add" : "image://theme/icon-m-back"
                    onClicked: {
                        root.statusMessage = ""
                        if (root.mode === "list") { root.mode = "generate"; root.typing = false; root.generate() }
                        else { root.clearSecrets(); root.mode = "list"; root.typing = false; root.editing = "" }
                    }
                }
                KpxButton {
                    visible: root.mode === "list" || root.mode === "generate" || root.mode === "save"
                    width: root.unit * 1.05; height: root.unit * 0.8
                    flat: true
                    iconSource: "image://theme/icon-m-device-lock"
                    onClicked: daemon.typedCall("Lock", [], function() { root.refreshStatus() })
                }
                KpxButton {
                    width: root.unit * 1.05; height: root.unit * 0.8
                    flat: true
                    iconSource: "image://theme/icon-m-setting"
                    onClicked: settingsUi.call("showPage", ["system_settings/system/text_input/keepass_kbd"])
                }
            }
        }

        Item {
            id: body
            anchors { top: header.bottom; left: parent.left; right: parent.right; bottom: parent.bottom
                      leftMargin: Theme.paddingSmall; rightMargin: Theme.paddingSmall }

            // ── Déverrouillage (style des champs Sailfish : texte, trait, libellé) ──
            Item {
                visible: root.mode === "locked"
                width: parent.width
                height: root.unit * 1.2

                Item {
                    id: masterField
                    anchors { left: parent.left; right: okButton.left; rightMargin: Theme.paddingMedium
                              leftMargin: Theme.paddingMedium; top: parent.top; bottom: parent.bottom }

                    Item {
                        id: masterTextArea
                        anchors { left: parent.left; right: eye.left; bottom: underline.top
                                  bottomMargin: Theme.paddingSmall }
                        height: masterText.implicitHeight
                        clip: true
                        Text {
                            id: masterText
                            // Fin du texte toujours visible pendant la saisie.
                            x: Math.min(0, parent.width - implicitWidth)
                            font.family: Theme.fontFamily
                            font.pixelSize: Theme.fontSizeMedium
                            font.letterSpacing: root.showMaster ? 0 : 2
                            textFormat: Text.PlainText
                            color: Theme.primaryColor
                            text: root.showMaster ? root.masterPassword
                                                  : Array(root.masterPassword.length + 1).join("•")
                        }
                        Rectangle {
                            // Curseur
                            x: Math.min(masterText.implicitWidth, parent.width - width)
                            width: 2; height: masterText.implicitHeight
                            color: Theme.highlightColor
                            SequentialAnimation on opacity {
                                loops: Animation.Infinite
                                running: root.mode === "locked"
                                NumberAnimation { to: 0; duration: 500 }
                                NumberAnimation { to: 1; duration: 500 }
                            }
                        }
                    }
                    IconButton {
                        id: eye
                        anchors { right: parent.right; verticalCenter: masterTextArea.verticalCenter }
                        width: Theme.iconSizeMedium + Theme.paddingSmall; height: width
                        icon.source: "image://theme/icon-splus-" + (root.showMaster ? "hide-password" : "show-password")
                        onClicked: root.showMaster = !root.showMaster
                    }
                    Rectangle {
                        id: underline
                        anchors { left: parent.left; right: parent.right; bottom: masterLabel.top
                                  bottomMargin: Theme.paddingSmall / 2 }
                        height: Math.max(1, Theme.pixelRatio * 2)
                        color: root.statusMessage !== "" ? Theme.errorColor : Theme.highlightColor
                    }
                    Label {
                        id: masterLabel
                        anchors { left: parent.left; bottom: parent.bottom }
                        font.pixelSize: Theme.fontSizeTiny
                        color: root.statusMessage !== "" ? Theme.errorColor : Theme.secondaryHighlightColor
                        text: "Mot de passe maître"
                    }
                }

                KpxButton {
                    id: okButton
                    anchors { right: parent.right; rightMargin: Theme.paddingSmall; verticalCenter: parent.verticalCenter }
                    width: Theme.iconSizeMedium + 2 * Theme.paddingMedium
                    height: Theme.iconSizeMedium + 2 * Theme.paddingSmall
                    highlighted: true
                    iconSource: "image://theme/icon-m-acknowledge"
                    active: root.masterPassword.length > 0 && root.busyText === ""
                    onClicked: root.unlock()
                }
            }

            // ── Liste : recherche, propositions, insertion ────────────
            Item {
                visible: root.mode === "list"
                anchors.fill: parent

                Rectangle {
                    id: searchRow
                    width: parent.width
                    height: root.unit * 0.8
                    radius: height / 2
                    color: root.typing ? Theme.rgba(Theme.highlightBackgroundColor, 0.22)
                                       : Theme.rgba(Theme.primaryColor, 0.08)
                    Icon {
                        id: searchIcon
                        anchors { left: parent.left; leftMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                        source: "image://theme/icon-m-search"
                        width: Theme.iconSizeSmallPlus; height: width
                        color: Theme.secondaryColor
                    }
                    Label {
                        anchors { left: searchIcon.right; right: clearQuery.left; leftMargin: Theme.paddingSmall
                                  verticalCenter: parent.verticalCenter }
                        truncationMode: TruncationMode.Fade
                        textFormat: Text.PlainText
                        color: root.query.length ? Theme.primaryColor : Theme.secondaryColor
                        text: root.query.length ? root.query + (root.typing ? "▏" : "") : "Rechercher"
                    }
                    MouseArea {
                        anchors.fill: parent
                        onClicked: { root.editing = "query"; root.typing = !root.typing }
                    }
                    IconButton {
                        id: clearQuery
                        anchors { right: parent.right; verticalCenter: parent.verticalCenter }
                        visible: root.query.length > 0
                        width: visible ? implicitWidth : 0
                        icon.source: "image://theme/icon-m-clear"
                        onClicked: { root.query = ""; root.search() }
                    }
                }

                SilicaListView {
                    id: list
                    anchors { top: searchRow.bottom; topMargin: Theme.paddingSmall
                              bottom: root.typing ? listKeyboardSpacer.top : insertRow.top
                              bottomMargin: Theme.paddingSmall }
                    width: parent.width
                    clip: true
                    model: root.listModel
                    delegate: Item {
                        width: list.width
                        height: modelData.kind === "header" ? root.unit * 0.5 : root.unit * 0.95

                        Label {
                            visible: modelData.kind === "header"
                            anchors { left: parent.left; leftMargin: Theme.paddingMedium; bottom: parent.bottom
                                      bottomMargin: Theme.paddingSmall / 2 }
                            text: modelData.kind === "header" ? modelData.text : ""
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.highlightColor
                        }

                        BackgroundItem {
                            id: entryItem
                            visible: modelData.kind === "entry"
                            anchors.fill: parent
                            readonly property var entry: modelData.kind === "entry" ? modelData.entry : null
                            highlighted: down || (entry !== null && root.selected !== null && root.selected.id === entry.id)
                            onClicked: root.chooseEntry(entry)

                            Rectangle {
                                id: avatar
                                anchors { left: parent.left; leftMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                                width: root.unit * 0.68; height: width
                                radius: width / 2
                                color: entryItem.entry ? root.avatarColor(entryItem.entry.title || "?") : "transparent"
                                Label {
                                    anchors.centerIn: parent
                                    text: entryItem.entry ? (entryItem.entry.title || "?").charAt(0).toUpperCase() : ""
                                    font.pixelSize: Theme.fontSizeMedium
                                    font.bold: true
                                    color: "white"
                                }
                            }
                            Column {
                                anchors { left: avatar.right; leftMargin: Theme.paddingMedium
                                          right: star.left; rightMargin: Theme.paddingSmall
                                          verticalCenter: parent.verticalCenter }
                                Label {
                                    width: parent.width
                                    text: entryItem.entry ? (entryItem.entry.title || "(sans titre)") : ""
                                    textFormat: Text.PlainText
                                    truncationMode: TruncationMode.Fade
                                    font.pixelSize: Theme.fontSizeSmall
                                    color: entryItem.highlighted ? Theme.highlightColor : Theme.primaryColor
                                }
                                Label {
                                    width: parent.width
                                    text: entryItem.entry ? entryItem.entry.username
                                                            + (entryItem.entry.group ? "  ·  " + entryItem.entry.group : "") : ""
                                    textFormat: Text.PlainText
                                    truncationMode: TruncationMode.Fade
                                    font.pixelSize: Theme.fontSizeExtraSmall
                                    color: entryItem.highlighted ? Theme.secondaryHighlightColor : Theme.secondaryColor
                                }
                            }
                            Icon {
                                id: star
                                anchors { right: parent.right; rightMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                                visible: modelData.suggested === true
                                source: "image://theme/icon-m-favorite-selected"
                                width: visible ? Theme.iconSizeSmall : 0; height: Theme.iconSizeSmall
                                color: Theme.highlightColor
                            }
                        }
                    }
                    Label {
                        visible: list.count === 0
                        anchors.centerIn: parent
                        text: root.query.length ? "Aucun résultat" : "Base vide"
                        color: Theme.secondaryColor
                    }
                    VerticalScrollDecorator {}
                }

                Item {
                    id: listKeyboardSpacer
                    anchors.bottom: parent.bottom
                    width: parent.width
                    height: miniKeyboard.height
                }

                Row {
                    id: insertRow
                    visible: !root.typing
                    anchors { bottom: parent.bottom; bottomMargin: Theme.paddingSmall }
                    width: parent.width
                    height: root.unit * 0.95
                    spacing: Theme.paddingSmall
                    KpxButton {
                        width: (parent.width - backspaceList.width - 2 * Theme.paddingSmall) / 2; height: parent.height
                        iconSource: "image://theme/icon-m-person"
                        text: "Identifiant"
                        active: root.selected !== null
                        highlighted: root.selected !== null && !root.passwordField
                        onClicked: root.insertField("username")
                    }
                    KpxButton {
                        width: (parent.width - backspaceList.width - 2 * Theme.paddingSmall) / 2; height: parent.height
                        iconSource: "image://theme/icon-m-keys"
                        text: "Mot de passe"
                        active: root.selected !== null
                        highlighted: root.selected !== null && root.passwordField
                        onClicked: root.insertField("password")
                    }
                    KpxBackspaceButton {
                        id: backspaceList
                        width: root.unit * 1.15; height: parent.height
                        onErase: root.appBackspace()
                    }
                }
            }

            // ── Générateur ────────────────────────────────────────────
            Column {
                visible: root.mode === "generate"
                width: parent.width
                spacing: Theme.paddingMedium
                Rectangle {
                    width: parent.width
                    height: root.unit * 1.1
                    radius: Theme.paddingMedium
                    color: Theme.rgba(Theme.primaryColor, 0.07)
                    border.width: 1
                    border.color: Theme.rgba(Theme.highlightColor, 0.4)
                    Label {
                        anchors { fill: parent; leftMargin: Theme.paddingLarge; rightMargin: refreshGen.width }
                        verticalAlignment: Text.AlignVCenter
                        horizontalAlignment: Text.AlignHCenter
                        font.family: "monospace"
                        fontSizeMode: Text.HorizontalFit
                        minimumPixelSize: Theme.fontSizeTiny
                        font.pixelSize: Theme.fontSizeMedium
                        textFormat: Text.StyledText
                        text: root.styledPassword(root.generated)
                    }
                    IconButton {
                        id: refreshGen
                        anchors { right: parent.right; verticalCenter: parent.verticalCenter }
                        icon.source: "image://theme/icon-m-refresh"
                        onClicked: root.generate()
                    }
                }
                Row {
                    width: parent.width
                    height: root.unit * 0.85
                    spacing: Theme.paddingMedium
                    KpxButton { width: root.unit * 0.85; height: parent.height; round: true; text: "−"
                        fontSize: Theme.fontSizeLarge
                        onClicked: if (root.genLength > 8) { root.genLength -= 1; root.generate() } }
                    Item {
                        width: parent.width - root.unit * 1.7 - 2 * parent.spacing
                        height: parent.height
                        Rectangle {
                            anchors.verticalCenter: parent.verticalCenter
                            width: parent.width; height: Theme.paddingSmall; radius: height / 2
                            color: Theme.rgba(Theme.primaryColor, 0.15)
                            Rectangle {
                                width: parent.width * (root.genLength - 8) / 56; height: parent.height
                                radius: height / 2
                                color: Theme.highlightColor
                            }
                        }
                        Label {
                            anchors { horizontalCenter: parent.horizontalCenter; top: parent.top }
                            text: root.genLength + " caractères"
                            font.pixelSize: Theme.fontSizeExtraSmall
                            color: Theme.highlightColor
                        }
                    }
                    KpxButton { width: root.unit * 0.85; height: parent.height; round: true; text: "+"
                        fontSize: Theme.fontSizeLarge
                        onClicked: if (root.genLength < 64) { root.genLength += 1; root.generate() } }
                }
                Row {
                    width: parent.width
                    height: root.unit * 0.8
                    spacing: Theme.paddingSmall
                    property real w: (width - 3 * Theme.paddingSmall) / 4
                    KpxButton { width: parent.w; height: parent.height; text: "a-z"; highlighted: root.genLower
                        onClicked: { root.genLower = !root.genLower; root.generate() } }
                    KpxButton { width: parent.w; height: parent.height; text: "A-Z"; highlighted: root.genUpper
                        onClicked: { root.genUpper = !root.genUpper; root.generate() } }
                    KpxButton { width: parent.w; height: parent.height; text: "0-9"; highlighted: root.genDigits
                        onClicked: { root.genDigits = !root.genDigits; root.generate() } }
                    KpxButton { width: parent.w; height: parent.height; text: "#$&"; highlighted: root.genSymbols
                        onClicked: { root.genSymbols = !root.genSymbols; root.generate() } }
                }
                Row {
                    width: parent.width
                    height: root.unit * 0.95
                    spacing: Theme.paddingSmall
                    KpxButton {
                        width: (parent.width - backspaceGen.width - 2 * Theme.paddingSmall) / 2; height: parent.height
                        iconSource: "image://theme/icon-m-edit"
                        text: "Insérer"
                        active: root.generated.length > 0
                        onClicked: root.commit(root.generated)
                    }
                    KpxBackspaceButton {
                        id: backspaceGen
                        width: root.unit * 1.15; height: parent.height
                        onErase: root.appBackspace()
                    }
                    KpxButton {
                        width: (parent.width - backspaceGen.width - 2 * Theme.paddingSmall) / 2; height: parent.height
                        iconSource: "image://theme/icon-m-acknowledge"
                        text: "Enregistrer…"
                        highlighted: true
                        active: root.generated.length > 0
                        onClicked: root.openSaveForm()
                    }
                }
            }

            // ── Enregistrement d'une nouvelle entrée ──────────────────
            SilicaFlickable {
                id: saveForm
                visible: root.mode === "save"
                anchors { top: parent.top; left: parent.left; right: parent.right
                          bottom: root.typing ? miniKeyboard.top : parent.bottom
                          leftMargin: Theme.paddingMedium; rightMargin: Theme.paddingMedium
                          bottomMargin: Theme.paddingSmall }
                clip: true
                contentHeight: saveColumn.height
                boundsBehavior: Flickable.StopAtBounds

                function ensureVisible(item) {
                    if (!item) return
                    if (item.y < contentY) contentY = item.y
                    else if (item.y + item.height > contentY + height)
                        contentY = Math.min(item.y + item.height - height, Math.max(0, contentHeight - height))
                }

                Column {
                    id: saveColumn
                    width: parent.width
                    spacing: Theme.paddingSmall

                    KpxLineField {
                        id: titleField
                        width: parent.width
                        label: "Titre"
                        placeholder: "Titre de l'entrée"
                        value: root.saveTitle
                        editing: root.typing && root.editing === "title"
                        onClicked: root.startEditing("title")
                    }
                    KpxLineField {
                        id: userField
                        width: parent.width
                        label: "Identifiant"
                        placeholder: "Identifiant ou e-mail"
                        value: root.saveUser
                        editing: root.typing && root.editing === "user"
                        onClicked: root.startEditing("user")
                    }
                    KpxLineField {
                        width: parent.width
                        label: "Mot de passe"
                        value: root.generated
                        secret: true
                        readOnly: true
                    }
                    KpxLineField {
                        id: urlField
                        width: parent.width
                        label: "URL"
                        placeholder: "https://… ou app://…"
                        value: root.saveUrl
                        editing: root.typing && root.editing === "url"
                        onClicked: root.startEditing("url")
                    }
                    Item { width: 1; height: Theme.paddingSmall }
                    KpxButton {
                        width: parent.width
                        height: root.unit * 0.9
                        iconSource: "image://theme/icon-m-acknowledge"
                        text: "Enregistrer dans KeePass"
                        highlighted: true
                        active: root.saveTitle.trim().length > 0 && root.busyText === ""
                        onClicked: root.saveEntry()
                    }
                }
                VerticalScrollDecorator {}
            }

            // ── Base introuvable / service arrêté ─────────────────────
            Column {
                visible: root.mode === "missing" || root.mode === "offline"
                anchors.centerIn: parent
                width: parent.width - 2 * Theme.paddingLarge
                spacing: Theme.paddingMedium
                Icon {
                    anchors.horizontalCenter: parent.horizontalCenter
                    source: "image://theme/icon-m-question"
                    color: Theme.secondaryColor
                }
                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                    color: Theme.secondaryColor
                    text: root.mode === "missing"
                          ? "Le fichier .kdbx est introuvable. Vérifiez le montage Nextcloud et ~/.config/keepass-kbd/config.json."
                          : "Démarrez le service : systemctl --user start keepass-kbd"
                }
            }

            KpxMiniKeyboard {
                id: miniKeyboard
                visible: root.mode === "locked" || (root.typing && (root.mode === "list" || root.mode === "save"))
                anchors.bottom: parent.bottom
                anchors.bottomMargin: Theme.paddingSmall
                width: parent.width
                rowHeight: root.unit * 0.8
                enterLabel: root.mode === "locked" ? "OK"
                            : root.mode === "save" ? (root.editing === "url" ? "Enreg." : "Suivant")
                            : "Fermer"
                onTyped: root.editText(text)
                onBackspace: root.editBackspace()
                onAccepted: root.editAccept()
            }
        }
    }
}
