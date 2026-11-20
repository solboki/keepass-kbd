//! Accès à la base KeePass : ouverture, recherche, ajout d'entrée et écriture vérifiée.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use keepass::db::{EntryId, GroupId};
use keepass::{Database, DatabaseKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Empreinte du fichier sur disque, pour détecter une modification extérieure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    pub len: u64,
    pub mtime: Option<SystemTime>,
    pub sha256: [u8; 32],
}

impl Fingerprint {
    pub fn of_bytes(bytes: &[u8], meta: &fs::Metadata) -> Self {
        Fingerprint {
            len: meta.len(),
            mtime: meta.modified().ok(),
            sha256: Sha256::digest(bytes).into(),
        }
    }
}

/// Métadonnées rapides (sans lecture du contenu) pour la surveillance périodique.
pub fn quick_stat(path: &Path) -> Option<(u64, Option<SystemTime>)> {
    fs::metadata(path).ok().map(|m| (m.len(), m.modified().ok()))
}

pub struct Credentials {
    pub password: Zeroizing<String>,
    pub keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl Credentials {
    pub fn key(&self) -> DatabaseKey {
        let mut key = DatabaseKey::new();
        if !self.password.is_empty() || self.keyfile.is_none() {
            key = key.with_password(&self.password);
        }
        if let Some(kf) = &self.keyfile {
            let mut cursor: &[u8] = kf;
            key = key.with_keyfile(&mut cursor).expect("lecture du fichier clé en mémoire");
        }
        key
    }
}

pub struct Vault {
    pub path: PathBuf,
    pub creds: Credentials,
    pub db: Database,
    pub raw: Zeroizing<Vec<u8>>,
    pub fingerprint: Fingerprint,
    /// Résultat (mis en cache par empreinte) du test de fidélité d'écriture.
    fidelity_ok_for: Option<[u8; 32]>,
}

#[derive(Serialize, Clone, Debug)]
pub struct EntrySummary {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub group: String,
}

fn read_file(path: &Path) -> Result<(Zeroizing<Vec<u8>>, Fingerprint), String> {
    let bytes = fs::read(path).map_err(|e| format!("lecture de {} : {e}", path.display()))?;
    let meta = fs::metadata(path).map_err(|e| format!("stat : {e}"))?;
    let fp = Fingerprint::of_bytes(&bytes, &meta);
    Ok((Zeroizing::new(bytes), fp))
}

pub fn open_err(e: keepass::db::DatabaseOpenError) -> String {
    let s = e.to_string();
    if s.to_lowercase().contains("key") || s.to_lowercase().contains("hmac") {
        "mot de passe maître ou fichier clé incorrect".to_string()
    } else {
        format!("ouverture impossible : {s}")
    }
}

impl Vault {
    pub fn open(path: &Path, creds: Credentials) -> Result<Vault, String> {
        let (raw, fingerprint) = read_file(path)?;
        let db = Database::parse(&raw, creds.key()).map_err(open_err)?;
        Ok(Vault {
            path: path.to_path_buf(),
            creds,
            db,
            raw,
            fingerprint,
            fidelity_ok_for: None,
        })
    }

    /// Relit le fichier s'il a changé. Renvoie Ok(true) si la base a été rechargée.
    pub fn reload_if_changed(&mut self) -> Result<bool, String> {
        let (raw, fp) = read_file(&self.path)?;
        if fp.sha256 == self.fingerprint.sha256 {
            self.fingerprint = fp; // mtime peut avoir bougé sans changement de contenu
            return Ok(false);
        }
        let db = Database::parse(&raw, self.creds.key()).map_err(open_err)?;
        self.db = db;
        self.raw = raw;
        self.fingerprint = fp;
        Ok(true)
    }

    pub fn entry_count(&self) -> usize {
        self.live_entries().count()
    }

    fn in_recycle_bin(&self, mut group: Option<GroupId>) -> bool {
        let Some(bin) = self.db.recycle_bin().map(|g| g.id()) else { return false };
        while let Some(gid) = group {
            if gid == bin {
                return true;
            }
            group = self.db.group(gid).and_then(|g| g.parent().map(|p| p.id()));
        }
        false
    }

    fn live_entries(&self) -> impl Iterator<Item = keepass::db::EntryRef<'_>> + '_ {
        self.db
            .iter_all_entries()
            .filter(move |e| !self.in_recycle_bin(Some(e.parent().id())))
    }

    pub fn summaries(&self) -> Vec<EntrySummary> {
        self.live_entries()
            .map(|e| EntrySummary {
                id: e.id().to_string(),
                title: e.get_title().unwrap_or("").to_string(),
                username: e.get_username().unwrap_or("").to_string(),
                url: e.get_url().unwrap_or("").to_string(),
                group: e.parent().name.clone(),
            })
            .collect()
    }

    /// Entrées correspondant à une origine (`https://site…` ou `app://identifiant`),
    /// avec un score : 3 hôte identique, 2 même domaine, 1 nom du site dans le titre.
    pub fn suggestions(&self, origin: &str) -> Vec<(u8, EntrySummary)> {
        let origin = origin.trim().to_lowercase();
        if origin.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let Some(app) = origin.strip_prefix("app://") {
            let app = app.trim_end_matches('/');
            for e in self.live_entries() {
                let url = e.get_url().unwrap_or("").trim().to_lowercase();
                let url_match = url.trim_end_matches('/') == origin.trim_end_matches('/');
                // Champs « AndroidApp… » de KeePassDX / Keepass2Android : androidapp://paquet
                let field_match = e.fields.iter().any(|(k, v)| {
                    k.to_lowercase().starts_with("androidapp")
                        && v.get().to_lowercase().trim_start_matches("androidapp://") == app
                });
                let title = e.get_title().unwrap_or("").to_lowercase();
                // Segments significatifs du nom de paquet : com.netflix.mediaclient → « netflix ».
                let tokens = app_tokens(app);
                let url_core = host_of(&url)
                    .map(|h| registrable(&h).split('.').next().unwrap_or("").to_string())
                    .unwrap_or_default();
                let score = if url_match || field_match {
                    3
                } else if !url_core.is_empty() && tokens.iter().any(|t| *t == url_core) {
                    2
                } else if tokens.iter().any(|t| title.contains(t.as_str())) {
                    1
                } else {
                    0
                };
                if score > 0 {
                    out.push((score, summary_of(&e)));
                }
            }
            return out;
        }
        let Some(host) = host_of(&origin) else { return out };
        let domain = registrable(&host);
        let core = domain.split('.').next().unwrap_or("").to_string();
        for e in self.live_entries() {
            let url = e.get_url().unwrap_or("").to_lowercase();
            let title = e.get_title().unwrap_or("").to_lowercase();
            let score = match host_of(&url) {
                Some(h) if h == host => 3,
                Some(h) if registrable(&h) == domain => 2,
                _ if core.len() >= 4 && title.contains(&core) => 1,
                _ => 0,
            };
            if score > 0 {
                out.push((score, summary_of(&e)));
            }
        }
        out
    }

    fn find(&self, id: &str) -> Option<keepass::db::EntryRef<'_>> {
        let uuid = uuid::Uuid::parse_str(id).ok()?;
        self.db.entry(EntryId::from(uuid))
    }

    pub fn field(&self, id: &str, field: &str) -> Result<String, String> {
        let e = self.find(id).ok_or("entrée introuvable")?;
        let key = match field {
            "username" => "UserName",
            "password" => "Password",
            "url" => "URL",
            "title" => "Title",
            "notes" => "Notes",
            other => other,
        };
        Ok(e.get(key).unwrap_or("").to_string())
    }

    fn target_group(&self, path: &str) -> Result<GroupId, String> {
        let parts: Vec<&str> = path.split('/').map(str::trim).filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(self.db.root().id());
        }
        self.db
            .root()
            .group_by_path(&parts)
            .map(|g| g.id())
            .ok_or_else(|| format!("groupe « {path} » introuvable dans la base"))
    }

    /// Vérifie que la bibliothèque réécrit la base actuelle sans perdre d'éléments XML.
    pub fn check_fidelity(&mut self) -> Result<(), String> {
        if self.fidelity_ok_for == Some(self.fingerprint.sha256) {
            return Ok(());
        }
        let original_xml = Zeroizing::new(
            Database::get_xml(&mut &self.raw[..], self.creds.key()).map_err(open_err)?,
        );
        let mut resaved = Zeroizing::new(Vec::new());
        self.db
            .save(&mut *resaved, self.creds.key())
            .map_err(|e| format!("sérialisation : {e}"))?;
        let resaved_xml = Zeroizing::new(
            Database::get_xml(&mut &resaved[..], self.creds.key()).map_err(open_err)?,
        );
        let diff = histogram_diff(&tag_histogram(&original_xml), &tag_histogram(&resaved_xml));
        if !diff.is_empty() {
            return Err(format!(
                "la réécriture perdrait ou modifierait des éléments de la base ({}). Écriture refusée.",
                diff.join(", ")
            ));
        }
        let reparsed = Database::parse(&resaved, self.creds.key()).map_err(open_err)?;
        if reparsed != self.db {
            return Err("la base relue après réécriture diffère de l'originale. Écriture refusée.".into());
        }
        self.fidelity_ok_for = Some(self.fingerprint.sha256);
        Ok(())
    }

    /// Ajoute une entrée et écrit le fichier de façon vérifiée et atomique.
    pub fn add_entry(
        &mut self,
        group_path: &str,
        title: &str,
        username: &str,
        password: &str,
        url: &str,
        notes: &str,
        backup_dir: &Path,
        backups_keep: usize,
    ) -> Result<String, String> {
        // 1. Repartir de la version la plus récente du fichier.
        self.reload_if_changed()?;
        // 2. Garantir que la bibliothèque ne perd rien sur cette base.
        self.check_fidelity()?;

        // 3. Construire la nouvelle base en mémoire.
        let group = self.target_group(group_path)?;
        let mut modified = self.db.clone();
        let new_id = {
            let mut g = modified.group_mut(group).ok_or("groupe cible introuvable")?;
            let mut e = g.add_entry();
            e.set_unprotected("Title", title);
            e.set_unprotected("UserName", username);
            e.set_protected("Password", password);
            e.set_unprotected("URL", url);
            e.set_unprotected("Notes", notes);
            e.id()
        };

        // 4. Sérialiser puis relire : le résultat doit être identique à la base voulue.
        let mut out = Zeroizing::new(Vec::new());
        modified
            .save(&mut *out, self.creds.key())
            .map_err(|e| format!("sérialisation : {e}"))?;
        let reparsed = Database::parse(&out, self.creds.key()).map_err(open_err)?;
        if reparsed != modified {
            return Err("vérification après écriture en mémoire échouée. Rien n'a été écrit.".into());
        }

        // 5. Sauvegarde de la version actuelle.
        backup(&self.raw, backup_dir, backups_keep)?;

        // 6. Refuser si le fichier a changé pendant la préparation.
        let (_, now_fp) = read_file(&self.path)?;
        if now_fp.sha256 != self.fingerprint.sha256 {
            return Err("la base a été modifiée ailleurs pendant l'enregistrement. Réessayez.".into());
        }

        // 7. Écriture atomique : fichier temporaire dans le même dossier puis renommage.
        let tmp = self.path.with_file_name(format!(
            ".{}.keepass-kbd.tmp",
            self.path.file_name().and_then(|s| s.to_str()).unwrap_or("db")
        ));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| format!("création du temporaire : {e}"))?;
            f.write_all(&out).map_err(|e| format!("écriture : {e}"))?;
            f.sync_all().map_err(|e| format!("synchronisation : {e}"))?;
        }
        let written = fs::read(&tmp).map_err(|e| format!("relecture du temporaire : {e}"))?;
        if written != *out {
            let _ = fs::remove_file(&tmp);
            return Err("le fichier temporaire relu ne correspond pas. Rien n'a été remplacé.".into());
        }
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("remplacement du fichier : {e}")
        })?;

        // 8. Adopter la nouvelle version.
        let (raw, fp) = read_file(&self.path)?;
        if *raw != *out {
            return Err("le fichier final relu diffère de ce qui a été écrit (sauvegarde disponible).".into());
        }
        self.db = modified;
        self.raw = raw;
        self.fingerprint = fp;
        self.fidelity_ok_for = Some(self.fingerprint.sha256);
        Ok(new_id.to_string())
    }
}

/// Segments d'un identifiant d'application utiles pour la correspondance.
fn app_tokens(app: &str) -> Vec<String> {
    const GENERIC: &[&str] = &[
        "com", "org", "net", "android", "apps", "app", "mobile", "client", "mediaclient", "main",
        "harbour", "sailfish", "jolla", "sailfishos", "google", "free", "lite", "beta", "release",
    ];
    app.split(['.', '-', '_'])
        .filter(|t| t.len() >= 4 && !GENERIC.contains(t))
        .map(String::from)
        .collect()
}

fn summary_of(e: &keepass::db::EntryRef<'_>) -> EntrySummary {
    EntrySummary {
        id: e.id().to_string(),
        title: e.get_title().unwrap_or("").to_string(),
        username: e.get_username().unwrap_or("").to_string(),
        url: e.get_url().unwrap_or("").to_string(),
        group: e.parent().name.clone(),
    }
}

/// Hôte d'une URL en minuscules (sans schéma, port, chemin ni « www. »). Accepte une URL sans schéma.
fn host_of(url: &str) -> Option<String> {
    let url = url.trim().to_lowercase();
    if url.is_empty() || url.starts_with("app://") || url.starts_with("androidapp://") {
        return None;
    }
    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or(&url);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit('@').next()?;
    let host = authority.split(':').next()?.trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    (host.contains('.') && !host.contains(' ')).then(|| host.to_string())
}

/// Domaine « enregistrable » approché : deux derniers labels, trois pour co.uk, com.fr, etc.
fn registrable(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host.to_string();
    }
    let second = labels[n - 2];
    let tld = labels[n - 1];
    let take = if tld.len() == 2 && matches!(second, "co" | "com" | "org" | "net" | "gouv" | "ac" | "gov" | "edu") {
        3
    } else {
        2
    };
    labels[n.saturating_sub(take)..].join(".")
}

fn backup(raw: &[u8], dir: &Path, keep: usize) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("dossier de sauvegarde : {e}"))?;
    let name = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f.kdbx").to_string();
    fs::write(dir.join(name), raw).map_err(|e| format!("sauvegarde : {e}"))?;
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("sauvegardes : {e}"))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "kdbx"))
        .collect();
    files.sort();
    while files.len() > keep.max(1) {
        let _ = fs::remove_file(files.remove(0));
    }
    Ok(())
}

/// Compte les balises ouvrantes non vides d'un document XML.
fn tag_histogram(xml: &[u8]) -> BTreeMap<String, usize> {
    let mut h = BTreeMap::new();
    let mut i = 0;
    while i < xml.len() {
        if xml[i] == b'<' && i + 1 < xml.len() && !matches!(xml[i + 1], b'/' | b'?' | b'!') {
            let start = i + 1;
            let mut j = start;
            while j < xml.len() && !matches!(xml[j], b' ' | b'>' | b'/' | b'\t' | b'\n' | b'\r') {
                j += 1;
            }
            let name = String::from_utf8_lossy(&xml[start..j]).to_string();
            let mut k = j;
            while k < xml.len() && xml[k] != b'>' {
                k += 1;
            }
            let self_closing = k > 0 && xml[k - 1] == b'/';
            let empty_pair = !self_closing && {
                let close = format!("</{name}>");
                xml[k + 1..].starts_with(close.as_bytes())
            };
            if !self_closing && !empty_pair {
                *h.entry(name).or_insert(0) += 1;
            }
            i = k;
        }
        i += 1;
    }
    h
}

fn histogram_diff(a: &BTreeMap<String, usize>, b: &BTreeMap<String, usize>) -> Vec<String> {
    let mut out = Vec::new();
    for k in a.keys().chain(b.keys()).collect::<std::collections::BTreeSet<_>>() {
        let (x, y) = (a.get(k).copied().unwrap_or(0), b.get(k).copied().unwrap_or(0));
        if x != y {
            out.push(format!("{k}: {x}→{y}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_token_matching() {
        assert_eq!(app_tokens("com.netflix.mediaclient"), vec!["netflix"]);
        assert_eq!(app_tokens("harbour-keepassrx"), vec!["keepassrx"]);
        assert!(app_tokens("com.android.app").is_empty());
    }

    #[test]
    fn hosts_and_domains() {
        assert_eq!(host_of("https://www.Amazon.fr/gp/x").as_deref(), Some("amazon.fr"));
        assert_eq!(host_of("compte.laposte.fr").as_deref(), Some("compte.laposte.fr"));
        assert_eq!(host_of("https://user@mail.example.org:8443/").as_deref(), Some("mail.example.org"));
        assert_eq!(host_of("app://jolla-email"), None);
        assert_eq!(registrable("compte.laposte.fr"), "laposte.fr");
        assert_eq!(registrable("login.bbc.co.uk"), "bbc.co.uk");
    }

    #[test]
    fn histogram_ignores_empty_elements() {
        let h = tag_histogram(b"<a><b/><c></c><d>x</d><d attr=\"1\">y</d></a>");
        assert_eq!(h.get("a"), Some(&1));
        assert_eq!(h.get("b"), None);
        assert_eq!(h.get("c"), None);
        assert_eq!(h.get("d"), Some(&2));
    }
}
