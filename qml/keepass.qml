// Disposition clavier « KeePass » : saisie d'identifiants depuis la base .kdbx
// via le service keepass-kbd (D-Bus de session org.keepasskbd.Daemon).
// Version @VERSION@
import QtQuick 2.0
import Sailfish.Silica 1.0
import com.meego.maliitquick 1.0
import Nemo.DBus 2.0
import ".."
import "KpxStrings.js" as S

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
    // Ajout d'un code à usage unique à une entrée (modes "otp" et "otpimages").
    property var otpEntry: null              // entrée concernée {id,title,username,has_totp}
    property string otpInput: ""             // clé secrète ou lien otpauth:// (saisi, collé ou lu)
    property bool showOtpKey: false
    property var otpPreview: null            // réponse de OtpPreview : {ok, issuer, account, code, remaining} ou {ok:false, error}
    property var imageItems: []              // images récentes où chercher un QR code
    property string editing: ""              // "master", "query", "title", "user", "url"

    // Langue du téléphone (anglais par défaut) et traduction des textes.
    readonly property string lang: S.lang(Qt.locale().name)
    function t(key, arg) { return S.tr(lang, key, arg) }

    readonly property int keyClick: typeof Maliit !== "undefined" ? Maliit.KeyClick : 0
    readonly property real unit: keyHeight > 0 ? keyHeight : Theme.itemSizeSmall
    readonly property bool passwordField: MInputMethodQuick.hiddenText
                                          || !!MInputMethodQuick.extensions.sensitiveInput
    // Champ numérique ou téléphone (code de double authentification probable) :
    // Maliit.NumberContentType ou PhoneNumberContentType, où le clavier Jolla affiche un pavé.
    readonly property bool numberField: MInputMethodQuick.contentType === 1 || MInputMethodQuick.contentType === 2

    // Codes à usage unique (TOTP) : option des Paramètres, désactivée par défaut.
    property bool totpEnabled: false
    // Base séparée des codes : "none" (codes dans la base principale), "locked", "unlocked", "missing".
    property string otpState: "none"
    property bool otpKeyfileOnly: false
    // Action à reprendre après le déverrouillage de la base des codes : "code" ou "add".
    property string otpPending: ""
    readonly property bool showTotp: totpEnabled && selected !== null && selected.has_totp === true
    property int totpRemaining: 0
    function updateTotpRemaining() {
        var p = selected && selected.totp_period > 0 ? selected.totp_period : 30
        totpRemaining = p - Math.floor(Date.now() / 1000) % p
    }
    onSelectedChanged: updateTotpRemaining()
    Timer {
        interval: 1000
        repeat: true
        running: root.showTotp && root.mode === "list" && MInputMethodQuick.active
        onTriggered: root.updateTotpRemaining()
    }
    function insertTotp() {
        if (!selected) return
        daemon.typedCall("Totp", [{ "type": "s", "value": selected.id }], function(json) {
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            if (r.otp_locked) { root.unlockOtpThen("code"); return }
            if (!r.code) return
            codeTyper.type(r.code)
        }, function() { refreshStatus() })
    }
    readonly property string originLabel: origin.indexOf("app://") === 0 ? origin.substring(6)
                                          : origin.replace(/^[a-z]+:\/\//, "").replace(/^www\./, "").split("/")[0]

    function clearSecrets() {
        masterPassword = ""
        showMaster = false
        showGenerated = false
        masterCursor = -1; titleCursor = -1; userCursor = -1; urlCursor = -1
        generated = ""
        saveTitle = ""; saveUser = ""; saveUrl = ""
        otpInput = ""; otpCursor = -1; otpPreview = null; showOtpKey = false; imageItems = []
        autofill.stop()
        codeTyper.stop(); codeTyper.queue = ""
    }

    // Saisie d'un code chiffre par chiffre, comme au pavé numérique de Jolla : certaines pages
    // ignorent un code envoyé d'un seul bloc. Puis retour au pavé numérique pour un champ numérique.
    Timer {
        id: codeTyper
        interval: 40
        repeat: true
        property string queue: ""
        function type(code) { queue = code; restart() }
        onTriggered: {
            if (queue.length > 0) {
                root.commit(queue.charAt(0))
                queue = queue.substring(1)
                return
            }
            stop()
            if (root.numberField) root.backToKeyboard()
        }
    }

    function commit(text) {
        if (text && text.length > 0)
            MInputMethodQuick.sendCommit(text)
    }

    property bool databaseConfigured: true
    property bool databaseDisabled: false       // base des mots de passe désactivée dans les Paramètres
    property bool firstRunPrompted: false
    function openSettings() {
        settingsUi.call("showPage", ["system_settings/system/text_input/keepass_kbd"])
    }

    // Choix du fichier .kdbx dans le clavier même : on reste dans l'application en cours.
    property string pickPath: ""
    property var pickListing: ({})
    property var pickItems: []
    function openPicker(p) {
        mode = "pick"; typing = false; editing = ""; statusMessage = ""
        daemon.typedCall("ListDir", [{ "type": "s", "value": p }], function(json) {
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            pickListing = r
            pickPath = r.path || ""
            var items = []
            if (r.parent && r.path !== "/") items.push({ kind: "up", name: ".." })
            var d = r.dirs || [], f = r.files || []
            for (var i = 0; i < d.length; ++i) items.push({ kind: "dir", name: d[i] })
            for (var j = 0; j < f.length; ++j) items.push({ kind: "file", name: f[j] })
            pickItems = items
            pickList.positionViewAtBeginning()
        }, function() { statusMessage = t("keepass-kbd service unreachable") })
    }
    function pickFile(name) {
        daemon.typedCall("SetDatabase", [{ "type": "s", "value": pickPath.replace(/\/$/, "") + "/" + name }], function(json) {
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            if (r.ok) {
                mode = "missing"; pickItems = []
                refreshStatus()
            } else {
                statusMessage = r.error || t("Unable to use this file")
            }
        }, function() { statusMessage = t("keepass-kbd service unreachable") })
    }

    // Dernière disposition utilisée avant KeePass (FUTO en général).
    property int previousIndex: -1

    function backToKeyboard() {
        clearSecrets()
        typing = false
        // Ouverte depuis le pavé numérique (touche KeePass) : y revenir d'abord, le
        // changement de disposition qui suit se fait alors sans être visible.
        if (numberField && typeof keyboard.updateLayout === "function")
            keyboard.updateLayout(true)
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
            totpEnabled = !!s.totp_enabled
            otpState = s.otp_state || "none"
            otpKeyfileOnly = !!s.otp_keyfile_only
            databaseDisabled = s.state === "disabled"
            if (s.state === "disabled") {
                if (mode === "pick") return
                mode = "missing"; typing = false; editing = ""
                entries = []; suggestions = []; selected = null
                autofill.stop()
            } else if (s.state === "unlocked") {
                if (mode === "locked" || mode === "offline" || mode === "missing") {
                    mode = "list"; typing = false; editing = ""
                }
                refreshOrigin()
                search()
            } else if (s.state === "missing") {
                databaseConfigured = !!s.database
                if (mode === "pick") return
                mode = "missing"
                // Premier lancement (aucune base choisie) : ouvrir le choix du fichier, une fois.
                if (!s.database && !firstRunPrompted && canvas.activeIndex === layoutIndex
                        && MInputMethodQuick.active) {
                    firstRunPrompted = true
                    openPicker("")
                }
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
                if (c.available) { callback(String(c.origin || "")); return }
                // Contexte du champ indisponible (cas habituel) : dernière page visitée, lue par le
                // service dans la base du navigateur ; sinon onglet « actif » noté par le navigateur
                // (souvent périmé).
                daemon.typedCall("BrowserOrigin", [], function(o) {
                    if (String(o || "") !== "") { callback(String(o)); return }
                    futo.typedCall("CurrentBrowserOrigin", [], function(cur) { callback(String(cur || "")) },
                                   function() { callback("") })
                }, function() { callback("") })
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
            // Autre site ou autre application : le filtre et le choix précédents ne valent plus.
            // Site inconnu (FUTO ne sait pas toujours le dire) : rien n'est remis à zéro.
            var key = originKey(o)
            if (key !== "" && key !== lastOriginKey) {
                lastOriginKey = key
                if (query !== "") { query = ""; search() }
                selected = null
                userChose = false
            }
            if (o === "") { suggestions = []; buildModel(); return }
            daemon.typedCall("Suggest", [{ "type": "s", "value": o }], function(json) {
                try { suggestions = JSON.parse(json) } catch (e) { suggestions = [] }
                // Présélection de la meilleure suggestion : les boutons du bas sont prêts. Une entrée
                // touchée par l'utilisateur reste choisie tant qu'on ne change pas de site.
                if (suggestions.length > 0 && (!selected || (!userChose && query === ""))) selected = bestSuggestion()
                buildModel()
            }, function() { suggestions = []; buildModel() })
        })
    }

    function buildModel() {
        var items = []
        if (query === "" && suggestions.length > 0) {
            var ids = {}
            items.push({ kind: "header", text: t("Suggestions for %1", originLabel) })
            for (var i = 0; i < suggestions.length; ++i) {
                items.push({ kind: "entry", entry: suggestions[i], suggested: true })
                ids[suggestions[i].id] = true
            }
            items.push({ kind: "header", text: t("All entries") })
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
                             if (selected) {
                                 for (var i = 0; i < entries.length; ++i)
                                     if (entries[i].id === selected.id) { selected = entries[i]; break }
                             }
                             buildModel()
                         }, function() { refreshStatus() })
    }

    // ── Base séparée des codes à usage unique ─────────────────────────
    // Verrouillée : mot de passe demandé sur le mini-clavier (mode "otplocked"), sauf si elle
    // s'ouvre par le seul fichier clé ; puis reprise de l'action (code ou ajout).
    function unlockOtpThen(action) {
        otpPending = action
        statusMessage = ""
        if (otpKeyfileOnly) { unlockOtp(""); return }
        masterPassword = ""; masterCursor = -1; showMaster = false
        mode = "otplocked"; editing = "master"; typing = false
    }

    function unlockOtp(pw) {
        busyText = t("Unlocking…")
        daemon.typedCall("UnlockOtp", [{ "type": "s", "value": pw }], function(json) {
            root.busyText = ""
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            if (r.ok) {
                root.masterPassword = ""
                root.statusMessage = ""
                root.otpState = "unlocked"
                var action = root.otpPending
                root.otpPending = ""
                root.mode = "list"; root.typing = false; root.editing = ""
                // Codes maintenant connus : suggestions et entrées recalculées.
                root.refreshOrigin(); root.search()
                if (action === "code") root.insertTotp()
                else if (action === "add") root.openOtpForm(root.selected)
            } else {
                root.statusMessage = r.error || root.t("unlock failed")
            }
        }, function() { root.busyText = ""; root.statusMessage = root.t("service unavailable") })
    }

    function unlock() {
        if (mode === "otplocked") {
            if ((masterPassword.length === 0 && !otpKeyfileOnly) || busyText !== "") return
            showMaster = false
            unlockOtp(masterPassword)
            return
        }
        if (masterPassword.length === 0 || busyText !== "") return
        showMaster = false
        busyText = t("Unlocking…")
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
                statusMessage = r.error || t("unlock failed")
            }
        }, function(err) { busyText = ""; statusMessage = t("service unavailable") })
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
        userChose = true
        typing = false
        // Champ numérique (code de double authentification) : le code de l'entrée, jamais son
        // identifiant ; sans code connu, l'entrée est seulement choisie (bouton du code prêt).
        if (numberField && !passwordField) {
            if (entry.has_totp === true) insertTotp()
            return
        }
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
                root.statusMessage = t("username and password inserted")
            } else if (++attempts > 10) {
                stop()
                root.statusMessage = t("tap the password field, then the key below")
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
                         function() { statusMessage = t("select at least one character type") })
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
            statusMessage = t("title is required")
            return
        }
        busyText = t("Saving to the database…")
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
                                 statusMessage = ""
                                 // La notification système confirme : retour à la disposition
                                 // précédente (FUTO) et fermeture du clavier.
                                 backToKeyboard()
                                 MInputMethodQuick.userHide()
                             } else {
                                 statusMessage = r.error || t("save failed")
                             }
                         }, function() { busyText = ""; statusMessage = t("service unavailable") })
    }

    // ── Édition au curseur (mot de passe maître, titre, identifiant, URL) ──
    // Position -1 = fin du texte.
    property int masterCursor: -1
    property int titleCursor: -1
    property int userCursor: -1
    property int urlCursor: -1
    property int otpCursor: -1
    property bool showGenerated: false

    function fieldValue(k) {
        return k === "master" ? masterPassword : k === "title" ? saveTitle
             : k === "user" ? saveUser : k === "url" ? saveUrl : k === "otp" ? otpInput : ""
    }
    function setFieldValue(k, v) {
        if (k === "master") masterPassword = v
        else if (k === "title") saveTitle = v
        else if (k === "user") saveUser = v
        else if (k === "url") saveUrl = v
        else if (k === "otp") otpInput = v
    }
    function cursorOf(k) {
        var c = k === "master" ? masterCursor : k === "title" ? titleCursor
              : k === "user" ? userCursor : k === "url" ? urlCursor : k === "otp" ? otpCursor : -1
        var len = fieldValue(k).length
        return c < 0 ? len : Math.min(c, len)
    }
    function setCursor(k, c) {
        if (k === "master") masterCursor = c
        else if (k === "title") titleCursor = c
        else if (k === "user") userCursor = c
        else if (k === "url") urlCursor = c
        else if (k === "otp") otpCursor = c
    }

    function editText(t) {
        if (editing === "query") { query += t; search(); return }
        var v = fieldValue(editing), c = cursorOf(editing)
        setFieldValue(editing, v.slice(0, c) + t + v.slice(c))
        setCursor(editing, c + t.length)
        if (editing === "master") statusMessage = ""
        if (editing === "otp") otpPreviewTimer.restart()
    }

    function editBackspace() {
        if (editing === "query") { query = query.slice(0, -1); search(); return }
        var v = fieldValue(editing), c = cursorOf(editing)
        if (c === 0) return
        setFieldValue(editing, v.slice(0, c - 1) + v.slice(c))
        setCursor(editing, c - 1)
        if (editing === "otp") otpPreviewTimer.restart()
    }

    function editAccept() {
        if (editing === "master") unlock()
        else if (editing === "query") typing = false
        else if (editing === "title") startEditing("user")
        else if (editing === "user") startEditing("url")
        else if (editing === "url") { typing = false; saveEntry() }
        else if (editing === "otp") { typing = false; updateOtpPreview() }
    }

    function startEditing(key) {
        editing = key
        typing = true
        ensureFieldTimer.restart()
    }
    Timer {
        id: ensureFieldTimer
        interval: 50
        onTriggered: if (root.mode === "save")
                         saveForm.ensureVisible(root.editing === "title" ? titleField
                                                : root.editing === "user" ? userField : urlField)
    }

    // ── Préremplissage du formulaire d'enregistrement ─────────────────
    // Identifiant tapé sur la page : mémorisé par FUTO (lastCredentialUsername),
    // sinon par le suivi de secours ci-dessous. Uniquement en mémoire vive.
    property string trackedUsername: ""
    property string lastOriginKey: ""
    property bool userChose: false           // entrée touchée dans la liste (pas une présélection)

    // Suggestion à présélectionner : le compte dont l'identifiant a été tapé sur la page, puis,
    // dans un champ numérique (code de double authentification), un compte qui a un code.
    function bestSuggestion() {
        var user = String(pageUsername() || "").trim().toLowerCase()
        if (user !== "") {
            for (var i = 0; i < suggestions.length; ++i)
                if (String(suggestions[i].username || "").trim().toLowerCase() === user) return suggestions[i]
        }
        if (numberField) {
            for (var j = 0; j < suggestions.length; ++j)
                if (suggestions[j].has_totp === true) return suggestions[j]
        }
        return suggestions[0]
    }

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

    // ── Ajout d'un code à usage unique (TOTP) à une entrée ────────────
    // Clé secrète ou lien otpauth:// saisi, collé, ou lu dans le QR code d'une capture d'écran.
    // Le service vérifie la saisie et donne le code actuel (aperçu), puis l'enregistre dans
    // le champ « otp » de l'entrée (format KeePassXC / KeePassDX).
    function openOtpForm(entry) {
        if (!entry) return
        clearSecrets()
        otpEntry = entry
        statusMessage = ""
        mode = "otp"
        // Ouverture sur les boutons (Coller, Capture d'écran) : le mini-clavier ne s'affiche
        // qu'en touchant le champ, sinon il les cache.
        typing = false; editing = ""
    }

    function updateOtpPreview() {
        if (!otpEntry || otpInput.trim() === "") { otpPreview = null; return }
        daemon.typedCall("OtpPreview", [{ "type": "s", "value": otpInput },
                                         { "type": "s", "value": otpEntry.title || "" },
                                         { "type": "s", "value": otpEntry.username || "" }],
                         function(json) {
                             var r = null
                             try { r = JSON.parse(json) } catch (e) {}
                             if (root.mode === "otp") root.otpPreview = r
                         }, function() { root.otpPreview = { ok: false, error: root.t("service unavailable") } })
    }
    Timer {
        id: otpPreviewTimer
        interval: 400
        onTriggered: root.updateOtpPreview()
    }
    // Le code de l'aperçu suit l'horloge (utile pour terminer l'activation sur le site).
    Timer {
        interval: 1000
        repeat: true
        running: root.mode === "otp" && root.otpPreview !== null && root.otpPreview.ok === true
                 && MInputMethodQuick.active
        onTriggered: root.updateOtpPreview()
    }

    function pasteOtp() {
        var c = String(Clipboard.text || "").trim()
        if (c === "") { statusMessage = t("The clipboard is empty"); return }
        statusMessage = ""
        otpInput = c; otpCursor = -1
        typing = false
        updateOtpPreview()
    }

    function openImages() {
        typing = false
        statusMessage = ""
        mode = "otpimages"
        daemon.typedCall("RecentImages", [{ "type": "i", "value": 12 }], function(json) {
            try { root.imageItems = JSON.parse(json) } catch (e) { root.imageItems = [] }
        }, function() { root.imageItems = []; root.statusMessage = root.t("service unavailable") })
    }

    function readImage(path) {
        if (busyText !== "") return
        busyText = t("Reading the QR code…")
        daemon.typedCall("OtpFromImage", [{ "type": "s", "value": path }], function(json) {
            root.busyText = ""
            var r = {}
            try { r = JSON.parse(json) } catch (e) {}
            if (r.ok) {
                root.otpInput = r.uri; root.otpCursor = -1
                root.otpPreview = r
                root.imageItems = []
                root.statusMessage = ""
                root.mode = "otp"
            } else {
                root.statusMessage = r.error || root.t("no QR code found")
            }
        }, function() { root.busyText = ""; root.statusMessage = root.t("service unavailable") })
    }

    function saveOtp() {
        if (!otpEntry || !otpPreview || !otpPreview.ok || busyText !== "") return
        busyText = t("Saving to the database…")
        daemon.typedCall("SetOtp", [{ "type": "s", "value": otpEntry.id },
                                     { "type": "s", "value": otpInput },
                                     { "type": "b", "value": otpEntry.has_totp === true }],
                         function(json) {
                             root.busyText = ""
                             var r = {}
                             try { r = JSON.parse(json) } catch (e) {}
                             if (r.ok) {
                                 // La notification système confirme ; l'entrée reste choisie et
                                 // son bouton « Code » apparaît au rechargement de la liste.
                                 root.clearSecrets()
                                 root.mode = "list"; root.typing = false; root.editing = ""
                                 root.statusMessage = root.t("Saving the one-time code…")
                             } else if (r.otp_locked) {
                                 root.unlockOtpThen("add")
                             } else {
                                 root.statusMessage = r.error || root.t("save failed")
                             }
                         }, function() { root.busyText = ""; root.statusMessage = root.t("service unavailable") })
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
            // Clavier fermé : le filtre repart de zéro ; l'entrée choisie reste (page suivante du
            // même site, champ du code par exemple), sauf changement de site (refreshOrigin).
            if (root.query !== "") { root.query = ""; root.search() }
            if (root.mode === "otp" || root.mode === "otpimages" || root.mode === "otplocked") {
                root.otpPending = ""
                root.mode = "list"
            }
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
                    source: root.mode === "locked" || root.mode === "otplocked" ? "image://theme/icon-m-device-lock"
                          : root.mode === "pick" ? "image://theme/icon-m-folder"
                          : root.mode === "otp" || root.mode === "otpimages" ? "image://theme/icon-m-timer"
                          : "image://theme/icon-m-keys"
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
                        text: root.mode === "generate" ? root.t("New password")
                              : root.mode === "save" ? root.t("Save to KeePass")
                              : root.mode === "pick" ? root.t("Choose a KeePass database")
                              : root.mode === "otp" ? root.t("One-time code")
                              : root.mode === "otplocked" ? root.t("One-time codes database")
                              : root.mode === "otpimages" ? root.t("Image with the QR code")
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
                              : root.mode === "pick" ? root.pickPath
                              : (root.mode === "otp" || root.mode === "otpimages") && root.otpEntry
                                ? (root.otpEntry.title || root.t("(untitled)"))
                              : root.mode === "locked" || root.mode === "otplocked" ? root.t("Database locked")
                              : root.mode === "missing" && root.databaseDisabled ? root.t("Database disabled")
                              : root.mode === "missing" ? root.t("Database not found")
                              : root.mode === "offline" ? root.t("Service stopped")
                              : root.origin !== "" ? root.originLabel
                              : root.t("%1 entries", root.entries.length)
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
                             || root.mode === "pick" || root.mode === "otp" || root.mode === "otpimages"
                             || root.mode === "otplocked"
                    width: root.unit * 1.05; height: root.unit * 0.8
                    flat: true
                    iconSource: root.mode === "list" ? "image://theme/icon-m-add" : "image://theme/icon-m-back"
                    onClicked: {
                        root.statusMessage = ""
                        if (root.mode === "pick") { root.mode = "missing"; root.pickItems = []; root.refreshStatus() }
                        else if (root.mode === "otpimages") { root.imageItems = []; root.mode = "otp" }
                        else if (root.mode === "otplocked") {
                            root.masterPassword = ""; root.otpPending = ""
                            root.mode = "list"; root.typing = false; root.editing = ""
                        }
                        else if (root.mode === "list") { root.mode = "generate"; root.typing = false; root.generate() }
                        else { root.clearSecrets(); root.mode = "list"; root.typing = false; root.editing = "" }
                    }
                }
                KpxButton {
                    visible: root.mode === "list" || root.mode === "generate" || root.mode === "save"
                             || root.mode === "otp" || root.mode === "otpimages"
                    width: root.unit * 1.05; height: root.unit * 0.8
                    flat: true
                    iconSource: "image://theme/icon-m-device-lock"
                    onClicked: daemon.typedCall("Lock", [], function() { root.refreshStatus() })
                }
                KpxButton {
                    width: root.unit * 1.05; height: root.unit * 0.8
                    flat: true
                    iconSource: "image://theme/icon-m-setting"
                    onClicked: root.openSettings()
                }
            }
        }

        Item {
            id: body
            anchors { top: header.bottom; left: parent.left; right: parent.right; bottom: parent.bottom
                      leftMargin: Theme.paddingSmall; rightMargin: Theme.paddingSmall }

            // ── Déverrouillage (style des champs Sailfish : texte, trait, libellé) ──
            Item {
                visible: root.mode === "locked" || root.mode === "otplocked"
                width: parent.width
                height: root.unit * 1.2

                KpxLineField {
                    id: masterField
                    anchors { left: parent.left; right: okButton.left; rightMargin: Theme.paddingMedium
                              leftMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                    label: root.mode === "otplocked" ? root.t("Password of the one-time codes database")
                                                     : root.t("Master password")
                    value: root.masterPassword
                    secret: true
                    showSecret: root.showMaster
                    editing: root.mode === "locked" || root.mode === "otplocked"
                    error: root.statusMessage !== ""
                    cursorPosition: root.cursorOf("master")
                    onCursorRequested: { root.editing = "master"; root.masterCursor = position }
                    onSecretToggled: root.showMaster = !root.showMaster
                }

                KpxButton {
                    id: okButton
                    anchors { right: parent.right; rightMargin: Theme.paddingSmall; verticalCenter: parent.verticalCenter }
                    width: Theme.iconSizeMedium + 2 * Theme.paddingMedium
                    height: Theme.iconSizeMedium + 2 * Theme.paddingSmall
                    highlighted: true
                    iconSource: "image://theme/icon-m-acknowledge"
                    active: (root.masterPassword.length > 0 || (root.mode === "otplocked" && root.otpKeyfileOnly))
                            && root.busyText === ""
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
                        text: root.query.length ? root.query + (root.typing ? "▏" : "") : root.t("Search")
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
                                    text: entryItem.entry ? (entryItem.entry.title || root.t("(untitled)")) : ""
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
                        text: root.query.length ? root.t("No results") : root.t("Empty database")
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
                    // 3e bouton (option TOTP) : « Code » si l'entrée en a un, sinon « + Code » pour l'ajouter.
                    readonly property bool otpSlot: root.totpEnabled && root.selected !== null
                    readonly property int buttons: otpSlot ? 3 : 2
                    readonly property real buttonWidth: (width - backspaceList.width - buttons * Theme.paddingSmall) / buttons
                    KpxButton {
                        width: parent.buttonWidth; height: parent.height
                        iconSource: "image://theme/icon-m-person"
                        text: root.t("Username")
                        active: root.selected !== null
                        highlighted: root.selected !== null && !root.passwordField && !(root.showTotp && root.numberField)
                        onClicked: root.insertField("username")
                    }
                    KpxButton {
                        width: parent.buttonWidth; height: parent.height
                        iconSource: "image://theme/icon-m-keys"
                        text: root.t("Password")
                        active: root.selected !== null
                        highlighted: root.selected !== null && root.passwordField
                        onClicked: root.insertField("password")
                    }
                    KpxButton {
                        visible: root.showTotp
                        width: parent.buttonWidth; height: parent.height
                        iconSource: "image://theme/icon-m-timer"
                        text: root.t("Code (%1 s)", root.totpRemaining)
                        highlighted: root.numberField && !root.passwordField
                        onClicked: root.insertTotp()
                    }
                    // Base des codes verrouillée : on ne sait pas encore si l'entrée a un code.
                    KpxButton {
                        visible: parent.otpSlot && !root.showTotp && root.otpState === "locked"
                        width: parent.buttonWidth; height: parent.height
                        iconSource: "image://theme/icon-m-device-lock"
                        text: root.t("Code")
                        highlighted: root.numberField && !root.passwordField
                        onClicked: root.unlockOtpThen("code")
                    }
                    KpxButton {
                        visible: parent.otpSlot && !root.showTotp && root.otpState !== "locked"
                        width: parent.buttonWidth; height: parent.height
                        iconSource: "image://theme/icon-m-add"
                        text: root.t("Code")
                        onClicked: root.openOtpForm(root.selected)
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
                            text: root.t("%1 characters", root.genLength)
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
                    KpxBackspaceButton {
                        id: backspaceGen
                        width: root.unit * 1.15; height: parent.height
                        onErase: root.appBackspace()
                    }
                    // « Utiliser » : insère le mot de passe dans le champ, puis ouvre
                    // la page de vérification des détails et d'enregistrement.
                    KpxButton {
                        width: parent.width - backspaceGen.width - Theme.paddingSmall; height: parent.height
                        iconSource: "image://theme/icon-m-acknowledge"
                        text: root.t("Use")
                        highlighted: true
                        active: root.generated.length > 0
                        onClicked: {
                            root.commit(root.generated)
                            root.openSaveForm()
                        }
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
                        label: root.t("Title")
                        placeholder: root.t("Entry title")
                        value: root.saveTitle
                        editing: root.typing && root.editing === "title"
                        cursorPosition: root.cursorOf("title")
                        onCursorRequested: root.titleCursor = position
                        onClicked: root.startEditing("title")
                    }
                    KpxLineField {
                        id: userField
                        width: parent.width
                        label: root.t("Username")
                        placeholder: root.t("Username or e-mail")
                        value: root.saveUser
                        editing: root.typing && root.editing === "user"
                        cursorPosition: root.cursorOf("user")
                        onCursorRequested: root.userCursor = position
                        onClicked: root.startEditing("user")
                    }
                    KpxLineField {
                        width: parent.width
                        label: root.t("Password")
                        value: root.generated
                        secret: true
                        showSecret: root.showGenerated
                        readOnly: true
                        onSecretToggled: root.showGenerated = !root.showGenerated
                    }
                    KpxLineField {
                        id: urlField
                        width: parent.width
                        label: "URL"
                        placeholder: "https://… ou app://…"
                        value: root.saveUrl
                        editing: root.typing && root.editing === "url"
                        cursorPosition: root.cursorOf("url")
                        onCursorRequested: root.urlCursor = position
                        onClicked: root.startEditing("url")
                    }
                    Item { width: 1; height: Theme.paddingSmall }
                    KpxButton {
                        width: parent.width
                        height: root.unit * 0.9
                        iconSource: "image://theme/icon-m-acknowledge"
                        text: root.t("Save to KeePass")
                        highlighted: true
                        active: root.saveTitle.trim().length > 0 && root.busyText === ""
                        onClicked: root.saveEntry()
                    }
                }
                VerticalScrollDecorator {}
            }

            // ── Code à usage unique : saisie, collage ou capture d'écran ──
            SilicaFlickable {
                id: otpForm
                visible: root.mode === "otp"
                anchors { top: parent.top; left: parent.left; right: parent.right
                          bottom: root.typing ? miniKeyboard.top : parent.bottom
                          leftMargin: Theme.paddingMedium; rightMargin: Theme.paddingMedium
                          bottomMargin: Theme.paddingSmall }
                clip: true
                contentHeight: otpColumn.height
                boundsBehavior: Flickable.StopAtBounds

                Column {
                    id: otpColumn
                    width: parent.width
                    spacing: Theme.paddingSmall

                    KpxLineField {
                        width: parent.width
                        label: root.t("Secret key or otpauth:// link")
                        placeholder: root.t("Key shown by the site")
                        value: root.otpInput
                        secret: true
                        showSecret: root.showOtpKey
                        editing: root.typing && root.editing === "otp"
                        error: root.otpPreview !== null && root.otpPreview.ok !== true
                        cursorPosition: root.cursorOf("otp")
                        onCursorRequested: root.otpCursor = position
                        onClicked: root.startEditing("otp")
                        onSecretToggled: root.showOtpKey = !root.showOtpKey
                    }
                    Row {
                        visible: !root.typing
                        width: parent.width
                        height: root.unit * 0.8
                        spacing: Theme.paddingSmall
                        KpxButton {
                            width: (parent.width - parent.spacing) / 2; height: parent.height
                            iconSource: "image://theme/icon-m-clipboard"
                            text: root.t("Paste")
                            onClicked: root.pasteOtp()
                        }
                        KpxButton {
                            width: (parent.width - parent.spacing) / 2; height: parent.height
                            iconSource: "image://theme/icon-m-image"
                            text: root.t("Screenshot")
                            onClicked: root.openImages()
                        }
                    }
                    // Aperçu : émetteur, compte et code actuel, ou l'erreur.
                    Rectangle {
                        visible: !root.typing
                        width: parent.width
                        height: root.unit * 1.3
                        radius: Theme.paddingMedium
                        color: Theme.rgba(Theme.primaryColor, 0.07)
                        border.width: 1
                        border.color: root.otpPreview && root.otpPreview.ok ? Theme.rgba(Theme.highlightColor, 0.4)
                                                                            : "transparent"
                        Column {
                            anchors { left: parent.left; right: parent.right; verticalCenter: parent.verticalCenter
                                      leftMargin: Theme.paddingMedium; rightMargin: Theme.paddingMedium }
                            Label {
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                truncationMode: TruncationMode.Fade
                                textFormat: Text.PlainText
                                font.pixelSize: Theme.fontSizeExtraSmall
                                color: root.otpPreview && root.otpPreview.ok ? Theme.secondaryHighlightColor : Theme.secondaryColor
                                wrapMode: root.otpPreview && !root.otpPreview.ok ? Text.Wrap : Text.NoWrap
                                text: !root.otpPreview ? root.t("Type or paste the key, or choose a screenshot of the QR code")
                                      : !root.otpPreview.ok ? (root.otpPreview.error || "")
                                      : [root.otpPreview.issuer, root.otpPreview.account].filter(function(x) { return !!x }).join("  ·  ")
                            }
                            Label {
                                visible: root.otpPreview !== null && root.otpPreview.ok === true
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                font.family: "monospace"
                                font.pixelSize: Theme.fontSizeLarge
                                color: Theme.highlightColor
                                text: root.otpPreview && root.otpPreview.ok
                                      ? String(root.otpPreview.code).replace(/^(\d{3})(\d{3})$/, "$1 $2")
                                        + "  ·  " + root.otpPreview.remaining + " s"
                                      : ""
                            }
                        }
                    }
                    Row {
                        visible: !root.typing
                        width: parent.width
                        height: root.unit * 0.9
                        spacing: Theme.paddingSmall
                        // Taper le code actuel : pour terminer l'activation sur le site.
                        KpxButton {
                            width: (parent.width - parent.spacing) * 0.4; height: parent.height
                            iconSource: "image://theme/icon-m-timer"
                            text: root.t("Type the code")
                            active: root.otpPreview !== null && root.otpPreview.ok === true
                            onClicked: root.commit(String(root.otpPreview.code))
                        }
                        KpxButton {
                            width: (parent.width - parent.spacing) * 0.6; height: parent.height
                            iconSource: "image://theme/icon-m-acknowledge"
                            text: root.otpEntry && root.otpEntry.has_totp ? root.t("Replace the code") : root.t("Save")
                            highlighted: true
                            active: root.otpPreview !== null && root.otpPreview.ok === true && root.busyText === ""
                            onClicked: root.saveOtp()
                        }
                    }
                }
                VerticalScrollDecorator {}
            }

            // ── Choix de l'image (capture d'écran du QR code) ─────────
            SilicaGridView {
                id: imageGrid
                visible: root.mode === "otpimages"
                anchors.fill: parent
                clip: true
                model: root.imageItems
                cellWidth: width / 4
                cellHeight: cellWidth * 1.5
                delegate: BackgroundItem {
                    width: imageGrid.cellWidth
                    height: imageGrid.cellHeight
                    onClicked: root.readImage(modelData.path)
                    Image {
                        anchors { fill: parent; margins: Theme.paddingSmall / 2 }
                        source: "file://" + modelData.path
                        sourceSize.width: imageGrid.cellWidth
                        fillMode: Image.PreserveAspectCrop
                        asynchronous: true
                        clip: true
                        opacity: parent.down ? 0.6 : 1.0
                    }
                }
                Label {
                    visible: imageGrid.count === 0
                    anchors.centerIn: parent
                    width: parent.width - 2 * Theme.paddingLarge
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                    color: Theme.secondaryColor
                    text: root.t("No recent screenshot or photo. Take a screenshot of the QR code, then come back here.")
                }
                VerticalScrollDecorator {}
            }

            // ── Base introuvable / non choisie / service arrêté ───────
            Column {
                visible: root.mode === "missing" || root.mode === "offline"
                anchors.centerIn: parent
                width: parent.width - 2 * Theme.paddingLarge
                spacing: Theme.paddingLarge
                Icon {
                    anchors.horizontalCenter: parent.horizontalCenter
                    source: root.mode === "missing" && !root.databaseConfigured ? "image://theme/icon-m-keys"
                                                                              : "image://theme/icon-m-question"
                    color: Theme.secondaryColor
                }
                Label {
                    width: parent.width
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                    color: Theme.secondaryColor
                    text: root.mode === "offline" ? root.t("Start the service: systemctl --user start keepass-kbd")
                          : root.databaseDisabled ? root.t("The password database is disabled in the KeePass Keyboard settings.")
                          : root.databaseConfigured ? root.t("The .kdbx file was not found. Check its location in the KeePass Keyboard settings.")
                          : root.t("No KeePass database selected yet.")
                }
                KpxButton {
                    visible: root.mode === "missing" && !root.databaseDisabled
                    anchors.horizontalCenter: parent.horizontalCenter
                    width: Math.min(parent.width, Theme.itemSizeHuge * 2.6)
                    height: root.unit * 0.9
                    highlighted: true
                    iconSource: "image://theme/icon-m-folder"
                    text: root.t("Choose the database file…")
                    onClicked: root.openPicker("")
                }
            }

            // ── Choix du fichier .kdbx ────────────────────────────────
            SilicaListView {
                id: pickList
                visible: root.mode === "pick"
                anchors.fill: parent
                clip: true
                model: root.pickItems
                delegate: BackgroundItem {
                    width: pickList.width
                    height: root.unit * 0.85
                    onClicked: {
                        if (modelData.kind === "up") root.openPicker(root.pickListing.parent)
                        else if (modelData.kind === "dir") root.openPicker(root.pickPath.replace(/\/$/, "") + "/" + modelData.name)
                        else root.pickFile(modelData.name)
                    }
                    Icon {
                        id: pickIcon
                        anchors { left: parent.left; leftMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                        source: modelData.kind === "file" ? "image://theme/icon-m-keys"
                              : modelData.kind === "up" ? "image://theme/icon-m-back" : "image://theme/icon-m-folder"
                        color: modelData.kind === "file" ? Theme.highlightColor : Theme.primaryColor
                    }
                    Label {
                        anchors { left: pickIcon.right; leftMargin: Theme.paddingMedium; right: parent.right
                                  rightMargin: Theme.paddingMedium; verticalCenter: parent.verticalCenter }
                        truncationMode: TruncationMode.Fade
                        font.pixelSize: Theme.fontSizeSmall
                        textFormat: Text.PlainText
                        color: modelData.kind === "file" ? Theme.highlightColor : Theme.primaryColor
                        text: modelData.kind === "up" ? root.t("Parent folder") : modelData.name
                    }
                }
                Label {
                    visible: pickList.count === 0
                    anchors.centerIn: parent
                    width: parent.width - 2 * Theme.paddingLarge
                    wrapMode: Text.Wrap
                    horizontalAlignment: Text.AlignHCenter
                    color: Theme.secondaryColor
                    text: root.pickListing.error ? root.t("Cannot open this folder") : root.t("No folder or .kdbx file here")
                }
                VerticalScrollDecorator {}
            }

            KpxMiniKeyboard {
                id: miniKeyboard
                visible: root.mode === "locked" || root.mode === "otplocked"
                         || (root.typing && (root.mode === "list" || root.mode === "save" || root.mode === "otp"))
                anchors.bottom: parent.bottom
                anchors.bottomMargin: Theme.paddingSmall
                width: parent.width
                rowHeight: root.unit * 0.8
                enterLabel: root.mode === "locked" || root.mode === "otplocked" || root.mode === "otp" ? root.t("OK")
                            : root.mode === "save" ? (root.editing === "url" ? root.t("Save") : root.t("Next"))
                            : root.t("Close")
                lang: root.lang
                onTyped: root.editText(text)
                onBackspace: root.editBackspace()
                onAccepted: root.editAccept()
            }
        }
    }
}
