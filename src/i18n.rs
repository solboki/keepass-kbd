//! Messages du service traduits selon la langue de la session (`LANG`), anglais par défaut.

use std::sync::OnceLock;

const LANGS: [&str; 9] = ["en", "fr", "de", "es", "it", "fi", "sv", "nl", "ru"];

/// Clé = texte anglais ; puis fr, de, es, it, fi, sv, nl, ru. « %1 » est remplacé par l'argument.
const TABLE: &[[&str; 9]] = &[
    ["incorrect master password or key file", "mot de passe maître ou fichier clé incorrect", "falsches Master-Passwort oder Schlüsseldatei", "contraseña maestra o archivo de clave incorrectos", "password principale o file chiave errati", "väärä pääsalasana tai avaintiedosto", "fel huvudlösenord eller nyckelfil", "onjuist hoofdwachtwoord of sleutelbestand", "неверный мастер-пароль или файл-ключ"],
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
