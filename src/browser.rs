//! Site ouvert dans le navigateur natif de Sailfish OS (sailfish-browser, moteur Gecko).
//!
//! Le navigateur n'expose pas l'adresse de l'onglet courant, et FUTO ne donne pas de contexte de
//! champ pour lui. Sa base `sailfish-browser.sqlite` enregistre en revanche chaque page visitée,
//! à la seconde près (`tab_history`), alors que l'onglet actif (`settings.activeTabId`) n'y est
//! pas tenu à jour. La dernière page visitée dans un onglet encore ouvert est donc le meilleur
//! indice. Seule l'origine (schéma et hôte) sort d'ici, jamais l'adresse complète.

use std::path::{Path, PathBuf};

pub fn sailfish_browser_db() -> PathBuf {
    crate::config::home().join(".local/share/org.sailfishos/browser/sailfish-browser.sqlite")
}

/// Origine (`https://hôte`) de la dernière page visitée dans un onglet ouvert, si elle est web.
pub fn last_visited_origin(db: &Path) -> Option<String> {
    use rusqlite::{Connection, OpenFlags};
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX).ok()?;
    let _ = conn.busy_timeout(std::time::Duration::from_millis(300));
    let url: String = conn
        .query_row(
            "SELECT l.url FROM tab_history h JOIN link l ON l.link_id = h.link_id \
             JOIN tab t ON t.tab_id = h.tab_id ORDER BY h.id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok()?;
    origin_of(&url)
}

/// `https://exemple.org/chemin?x` → `https://exemple.org` (http et https seulement).
fn origin_of(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?.to_ascii_lowercase();
    (!host.is_empty()).then(|| format!("{scheme}://{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_visited_tab_wins() {
        let dir = std::env::temp_dir().join(format!("keepass-kbd-browser-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sailfish-browser.sqlite");
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch(
            "CREATE TABLE tab (tab_id INTEGER PRIMARY KEY, tab_history_id INTEGER);
             CREATE TABLE tab_history (id INTEGER PRIMARY KEY AUTOINCREMENT, tab_id INTEGER, link_id INTEGER, date INT);
             CREATE TABLE link (link_id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, title TEXT, thumb_path TEXT);
             CREATE TABLE settings (name TEXT PRIMARY KEY, value TEXT);
             INSERT INTO settings VALUES ('activeTabId', '1');
             INSERT INTO tab VALUES (1, 1), (2, 3);
             INSERT INTO link (url) VALUES ('https://www.google.com/search?q=x'), ('https://fermé.example/'),
                                           ('https://www.amazon.fr/ap/signin?openid=1');
             INSERT INTO tab_history (tab_id, link_id, date) VALUES (1, 1, 10), (2, 3, 30), (9, 2, 40);",
        )
        .unwrap();
        drop(c);
        // L'onglet 9 est fermé ; l'onglet « actif » noté (1) est périmé : dernière page = amazon.
        assert_eq!(last_visited_origin(&path).as_deref(), Some("https://www.amazon.fr"));
        assert_eq!(last_visited_origin(&dir.join("absent.sqlite")), None);
        assert_eq!(origin_of("about:blank"), None);
        assert_eq!(origin_of("HTTPS://User@Laposte.net:443/x").as_deref(), Some("https://laposte.net:443"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
