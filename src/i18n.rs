//! Messages du service traduits selon la langue de la session (`LANG`), anglais par défaut.

use std::sync::OnceLock;

const LANGS: [&str; 9] = ["en", "fr", "de", "es", "it", "fi", "sv", "nl", "ru"];

/// Clé = texte anglais ; puis fr, de, es, it, fi, sv, nl, ru. « %1 » est remplacé par l'argument.
const TABLE: &[[&str; 9]] = &[
    ["incorrect master password or key file", "mot de passe maître ou fichier clé incorrect", "falsches Master-Passwort oder Schlüsseldatei", "contraseña maestra o archivo de clave incorrectos", "password principale o file chiave errati", "väärä pääsalasana tai avaintiedosto", "fel huvudlösenord eller nyckelfil", "onjuist hoofdwachtwoord of sleutelbestand", "неверный мастер-пароль или файл-ключ"],
    ["one-time codes are disabled", "codes à usage unique désactivés", "Einmalcodes deaktiviert", "códigos de un solo uso desactivados", "codici monouso disattivati", "kertakäyttökoodit pois käytöstä", "engångskoder är avstängda", "eenmalige codes uitgeschakeld", "одноразовые коды отключены"],
    ["no one-time code for this entry", "pas de code à usage unique pour cette entrée", "kein Einmalcode für diesen Eintrag", "esta entrada no tiene código de un solo uso", "nessun codice monouso per questa voce", "tällä merkinnällä ei ole kertakäyttökoodia", "posten har ingen engångskod", "geen eenmalige code voor dit item", "у этой записи нет одноразового кода"],
    ["database locked", "base verrouillée", "Datenbank gesperrt", "base de datos bloqueada", "database bloccato", "tietokanta lukittu", "databasen är låst", "database vergrendeld", "база заблокирована"],
    ["locked", "verrouillée", "gesperrt", "bloqueada", "bloccato", "lukittu", "låst", "vergrendeld", "заблокирована"],
    ["locked (new database)", "verrouillée (nouvelle base)", "gesperrt (neue Datenbank)", "bloqueada (nueva base)", "bloccato (nuovo database)", "lukittu (uusi tietokanta)", "låst (ny databas)", "vergrendeld (nieuwe database)", "заблокирована (новая база)"],
    ["uninstalling", "désinstallation", "Deinstallation", "desinstalando", "disinstallazione", "poistetaan", "avinstallerar", "verwijderen", "удаление"],
    ["this file is not a readable KeePass (.kdbx) database", "ce fichier n'est pas une base KeePass (.kdbx) lisible", "diese Datei ist keine lesbare KeePass-Datenbank (.kdbx)", "este archivo no es una base KeePass (.kdbx) legible", "questo file non è un database KeePass (.kdbx) leggibile", "tiedosto ei ole luettava KeePass-tietokanta (.kdbx)", "filen är inte en läsbar KeePass-databas (.kdbx)", "dit bestand is geen leesbare KeePass-database (.kdbx)", "файл не является читаемой базой KeePass (.kdbx)"],
    ["a save is already in progress", "un enregistrement est déjà en cours", "es wird bereits gespeichert", "ya se está guardando", "salvataggio già in corso", "tallennus on jo käynnissä", "sparande pågår redan", "er wordt al opgeslagen", "сохранение уже выполняется"],
    ["the database was locked during the save", "la base a été verrouillée pendant l'enregistrement", "die Datenbank wurde während des Speicherns gesperrt", "la base se bloqueó durante el guardado", "il database è stato bloccato durante il salvataggio", "tietokanta lukittiin tallennuksen aikana", "databasen låstes under sparandet", "de database werd tijdens het opslaan vergrendeld", "база была заблокирована во время сохранения"],
    ["KeePass entry saved", "Entrée KeePass enregistrée", "KeePass-Eintrag gespeichert", "Entrada de KeePass guardada", "Voce KeePass salvata", "KeePass-merkintä tallennettu", "KeePass-post sparad", "KeePass-item opgeslagen", "Запись KeePass сохранена"],
    ["“%1” was added to the database", "« %1 » a été ajoutée à la base", "„%1“ wurde der Datenbank hinzugefügt", "«%1» se añadió a la base", "«%1» è stata aggiunta al database", "”%1” lisättiin tietokantaan", "”%1” lades till i databasen", "‘%1’ is aan de database toegevoegd", "«%1» добавлена в базу"],
    ["KeePass save failed", "Échec de l'enregistrement KeePass", "Speichern in KeePass fehlgeschlagen", "Error al guardar en KeePass", "Salvataggio KeePass non riuscito", "KeePass-tallennus epäonnistui", "Det gick inte att spara i KeePass", "Opslaan in KeePass mislukt", "Не удалось сохранить в KeePass"],
    ["master password required again", "mot de passe maître à ressaisir", "Master-Passwort erneut erforderlich", "hay que volver a introducir la contraseña maestra", "reinserire la password principale", "pääsalasana on annettava uudelleen", "huvudlösenordet måste anges igen", "hoofdwachtwoord opnieuw vereist", "требуется снова ввести мастер-пароль"],
    ["database reloaded", "base rechargée", "Datenbank neu geladen", "base recargada", "database ricaricato", "tietokanta ladattu uudelleen", "databasen har lästs in igen", "database opnieuw geladen", "база перезагружена"],
    ["locked: %1", "verrouillée : %1", "gesperrt: %1", "bloqueada: %1", "bloccato: %1", "lukittu: %1", "låst: %1", "vergrendeld: %1", "заблокирована: %1"],
    ["the database was reloaded during the save. Try again.", "la base a été rechargée pendant l'enregistrement. Réessayez.", "die Datenbank wurde während des Speicherns neu geladen. Bitte erneut versuchen.", "la base se recargó durante el guardado. Inténtelo de nuevo.", "il database è stato ricaricato durante il salvataggio. Riprova.", "tietokanta ladattiin uudelleen tallennuksen aikana. Yritä uudelleen.", "databasen lästes in igen under sparandet. Försök igen.", "de database werd tijdens het opslaan opnieuw geladen. Probeer het opnieuw.", "база была перезагружена во время сохранения. Повторите попытку."],
    ["the database was modified elsewhere during the save. Try again.", "la base a été modifiée ailleurs pendant l'enregistrement. Réessayez.", "die Datenbank wurde während des Speicherns anderswo geändert. Bitte erneut versuchen.", "la base se modificó en otro lugar durante el guardado. Inténtelo de nuevo.", "il database è stato modificato altrove durante il salvataggio. Riprova.", "tietokantaa muutettiin muualla tallennuksen aikana. Yritä uudelleen.", "databasen ändrades på annat håll under sparandet. Försök igen.", "de database werd elders gewijzigd tijdens het opslaan. Probeer het opnieuw.", "база была изменена в другом месте во время сохранения. Повторите попытку."],
    ["rewriting would lose or alter database elements (%1). Write refused.", "la réécriture perdrait ou modifierait des éléments de la base (%1). Écriture refusée.", "Neuschreiben würde Datenbankelemente verlieren oder verändern (%1). Schreiben abgelehnt.", "reescribir perdería o alteraría elementos de la base (%1). Escritura rechazada.", "la riscrittura perderebbe o altererebbe elementi del database (%1). Scrittura rifiutata.", "uudelleenkirjoitus menettäisi tai muuttaisi tietokannan osia (%1). Kirjoitus estetty.", "omskrivning skulle förlora eller ändra databaselement (%1). Skrivning nekad.", "herschrijven zou database-elementen verliezen of wijzigen (%1). Schrijven geweigerd.", "перезапись потеряла бы или изменила элементы базы (%1). Запись отклонена."],
    ["locked (sleep)", "verrouillée (mise en veille)", "gesperrt (Ruhezustand)", "bloqueada (reposo)", "bloccato (sospensione)", "lukittu (lepotila)", "låst (viloläge)", "vergrendeld (slaapstand)", "заблокирована (сон)"],
    ["locked with the screen", "verrouillée avec l'écran", "mit dem Bildschirm gesperrt", "bloqueada con la pantalla", "bloccato con lo schermo", "lukittu näytön mukana", "låst med skärmen", "vergrendeld met het scherm", "заблокирована вместе с экраном"],
    ["uninstall script not found", "script de désinstallation introuvable", "Deinstallationsskript nicht gefunden", "no se encontró el script de desinstalación", "script di disinstallazione non trovato", "poistoskriptiä ei löydy", "avinstallationsskriptet hittades inte", "verwijderscript niet gevonden", "сценарий удаления не найден"],
    ["this is not a valid one-time code key", "ce n'est pas une clé de code à usage unique valide", "das ist kein gültiger Schlüssel für Einmalcodes", "no es una clave de código de un solo uso válida", "non è una chiave valida per codici monouso", "tämä ei ole kelvollinen kertakäyttökoodin avain", "det här är ingen giltig nyckel för engångskoder", "dit is geen geldige sleutel voor eenmalige codes", "это не действительный ключ одноразовых кодов"],
    ["Google Authenticator exports (otpauth-migration) are not supported", "les exports de Google Authenticator (otpauth-migration) ne sont pas pris en charge", "Exporte aus Google Authenticator (otpauth-migration) werden nicht unterstützt", "las exportaciones de Google Authenticator (otpauth-migration) no son compatibles", "le esportazioni di Google Authenticator (otpauth-migration) non sono supportate", "Google Authenticatorin vientejä (otpauth-migration) ei tueta", "exporter från Google Authenticator (otpauth-migration) stöds inte", "exports van Google Authenticator (otpauth-migration) worden niet ondersteund", "экспорт Google Authenticator (otpauth-migration) не поддерживается"],
    ["counter-based codes (HOTP) are not supported", "les codes à compteur (HOTP) ne sont pas pris en charge", "zählerbasierte Codes (HOTP) werden nicht unterstützt", "los códigos basados en contador (HOTP) no son compatibles", "i codici a contatore (HOTP) non sono supportati", "laskuripohjaisia koodeja (HOTP) ei tueta", "räknarbaserade koder (HOTP) stöds inte", "codes op basis van een teller (HOTP) worden niet ondersteund", "коды на основе счётчика (HOTP) не поддерживаются"],
    ["entry not found", "entrée introuvable", "Eintrag nicht gefunden", "entrada no encontrada", "voce non trovata", "merkintää ei löydy", "posten hittades inte", "item niet gevonden", "запись не найдена"],
    ["this entry already has a one-time code", "cette entrée a déjà un code à usage unique", "dieser Eintrag hat bereits einen Einmalcode", "esta entrada ya tiene un código de un solo uso", "questa voce ha già un codice monouso", "tällä merkinnällä on jo kertakäyttökoodi", "posten har redan en engångskod", "dit item heeft al een eenmalige code", "у этой записи уже есть одноразовый код"],
    ["One-time code saved", "Code à usage unique enregistré", "Einmalcode gespeichert", "Código de un solo uso guardado", "Codice monouso salvato", "Kertakäyttökoodi tallennettu", "Engångskod sparad", "Eenmalige code opgeslagen", "Одноразовый код сохранён"],
    ["“%1” now has a one-time code", "« %1 » a maintenant un code à usage unique", "„%1“ hat jetzt einen Einmalcode", "«%1» ya tiene un código de un solo uso", "«%1» ora ha un codice monouso", "”%1” sai kertakäyttökoodin", "”%1” har nu en engångskod", "‘%1’ heeft nu een eenmalige code", "У «%1» теперь есть одноразовый код"],
    ["this image cannot be read (%1)", "impossible de lire cette image (%1)", "dieses Bild kann nicht gelesen werden (%1)", "no se puede leer esta imagen (%1)", "impossibile leggere questa immagine (%1)", "kuvaa ei voi lukea (%1)", "bilden kan inte läsas (%1)", "deze afbeelding kan niet worden gelezen (%1)", "не удаётся прочитать изображение (%1)"],
    ["no QR code found in this image", "aucun QR code trouvé dans cette image", "kein QR-Code in diesem Bild gefunden", "no se encontró ningún código QR en esta imagen", "nessun codice QR trovato in questa immagine", "kuvasta ei löytynyt QR-koodia", "ingen QR-kod hittades i bilden", "geen QR-code gevonden in deze afbeelding", "QR-код на изображении не найден"],
    ["this QR code does not contain a one-time code", "ce QR code ne contient pas de code à usage unique", "dieser QR-Code enthält keinen Einmalcode", "este código QR no contiene un código de un solo uso", "questo codice QR non contiene un codice monouso", "QR-koodi ei sisällä kertakäyttökoodia", "QR-koden innehåller ingen engångskod", "deze QR-code bevat geen eenmalige code", "этот QR-код не содержит одноразового кода"],
    ["key file unreadable (%1)", "fichier clé illisible (%1)", "Schlüsseldatei nicht lesbar (%1)", "archivo de clave ilegible (%1)", "file chiave illeggibile (%1)", "avaintiedostoa ei voi lukea (%1)", "nyckelfilen kan inte läsas (%1)", "sleutelbestand onleesbaar (%1)", "файл-ключ не читается (%1)"],
    ["cannot create the file (%1)", "impossible de créer le fichier (%1)", "Datei kann nicht erstellt werden (%1)", "no se puede crear el archivo (%1)", "impossibile creare il file (%1)", "tiedostoa ei voi luoda (%1)", "filen kan inte skapas (%1)", "bestand kan niet worden gemaakt (%1)", "не удаётся создать файл (%1)"],
    ["a password or a key file is required", "un mot de passe ou un fichier clé est nécessaire", "ein Passwort oder eine Schlüsseldatei ist erforderlich", "se necesita una contraseña o un archivo de clave", "serve una password o un file chiave", "salasana tai avaintiedosto tarvitaan", "ett lösenord eller en nyckelfil krävs", "een wachtwoord of sleutelbestand is vereist", "нужен пароль или файл-ключ"],
    ["the one-time code database is locked", "la base des codes à usage unique est verrouillée", "die Datenbank der Einmalcodes ist gesperrt", "la base de códigos de un solo uso está bloqueada", "il database dei codici monouso è bloccato", "kertakäyttökoodien tietokanta on lukittu", "databasen för engångskoder är låst", "de database met eenmalige codes is vergrendeld", "база одноразовых кодов заблокирована"],
    ["no separate database for one-time codes", "pas de base séparée pour les codes à usage unique", "keine separate Datenbank für Einmalcodes", "no hay base separada para los códigos de un solo uso", "nessun database separato per i codici monouso", "kertakäyttökoodeille ei ole erillistä tietokantaa", "ingen separat databas för engångskoder", "geen aparte database voor eenmalige codes", "нет отдельной базы для одноразовых кодов"],
    ["choose a database different from the password database", "choisissez une base différente de celle des mots de passe", "wählen Sie eine andere Datenbank als die Passwortdatenbank", "elija una base distinta de la de contraseñas", "scegli un database diverso da quello delle password", "valitse eri tietokanta kuin salasanojen tietokanta", "välj en annan databas än lösenordsdatabasen", "kies een andere database dan die van de wachtwoorden", "выберите базу, отличную от базы паролей"],
    ["choose a key file first", "choisissez d'abord un fichier clé", "wählen Sie zuerst eine Schlüsseldatei", "elija primero un archivo de clave", "scegli prima un file chiave", "valitse ensin avaintiedosto", "välj först en nyckelfil", "kies eerst een sleutelbestand", "сначала выберите файл-ключ"],
    ["the file is not responding (%1)", "le fichier ne répond pas (%1)", "die Datei antwortet nicht (%1)", "el archivo no responde (%1)", "il file non risponde (%1)", "tiedosto ei vastaa (%1)", "filen svarar inte (%1)", "het bestand reageert niet (%1)", "файл не отвечает (%1)"],
    ["the password database is disabled", "la base des mots de passe est désactivée", "die Passwortdatenbank ist deaktiviert", "la base de contraseñas está desactivada", "il database delle password è disattivato", "salasanatietokanta on poistettu käytöstä", "lösenordsdatabasen är avstängd", "de wachtwoorddatabase is uitgeschakeld", "база паролей отключена"],
];

fn lang_index() -> usize {
    static IDX: OnceLock<usize> = OnceLock::new();
    *IDX.get_or_init(|| {
        let lang = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .find_map(|v| std::env::var(v).ok().filter(|s| !s.is_empty()))
            .unwrap_or_default();
        let code = lang.split(['_', '.', '-']).next().unwrap_or("").to_lowercase();
        LANGS.iter().position(|l| *l == code).unwrap_or(0)
    })
}

/// Texte traduit (la clé anglaise si elle est inconnue).
pub fn tr(key: &str) -> String {
    let i = lang_index();
    TABLE.iter().find(|row| row[0] == key).map(|row| row[i]).unwrap_or(key).to_string()
}

/// Texte traduit avec un argument « %1 ».
pub fn tr1(key: &str, arg: &str) -> String {
    tr(key).replace("%1", arg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_complete() {
        for row in TABLE {
            assert!(row.iter().all(|s| !s.is_empty()), "traduction vide : {}", row[0]);
            if row[0].contains("%1") {
                assert!(row.iter().all(|s| s.contains("%1")), "%1 manquant : {}", row[0]);
            }
        }
    }
}
