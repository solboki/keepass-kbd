//! Accès à la base KeePass : ouverture, recherche, ajout d'entrée et écriture vérifiée.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant, SystemTime};

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

/// Délai maximal d'une lecture de fichier (base, fichier clé). Au-delà, le fichier est jugé
/// injoignable : montage réseau (rclone, sshfs…) qui ne répond plus, carte SD retirée…
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Délai maximal d'un `stat` de surveillance.
pub const STAT_TIMEOUT: Duration = Duration::from_secs(3);

/// Lectures en cours : (fichier, début). Une lecture bloquée dans le noyau ne peut pas être
/// interrompue ; son fil reste en attente et n'est retiré d'ici que s'il finit par aboutir.
static IN_FLIGHT: Mutex<Vec<(PathBuf, Instant)>> = Mutex::new(Vec::new());

/// Exécute `f` (accès au fichier `path`) sur un fil à part et attend au plus `timeout`.
/// Tant qu'un accès précédent au même fichier est bloqué au-delà du délai, échoue aussitôt
/// au lieu d'empiler un fil de plus : un seul fil par fichier peut rester coincé.
pub fn with_timeout<T: Send + 'static>(
    path: &Path,
    timeout: Duration,
    f: impl FnOnce(&Path) -> T + Send + 'static,
) -> Result<T, String> {
    let not_responding = || crate::i18n::tr1("the file is not responding (%1)", &path.display().to_string());
    let started = Instant::now();
    {
        let mut inflight = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if inflight.iter().any(|(p, t)| p == path && t.elapsed() > timeout) {
            return Err(not_responding());
        }
        inflight.push((path.to_path_buf(), started));
    }
    let (tx, rx) = mpsc::channel();
    let owned = path.to_path_buf();
    let spawned = std::thread::Builder::new().name("file-io".into()).spawn(move || {
        let r = f(&owned);
        let mut inflight = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(i) = inflight.iter().position(|(p, t)| *p == owned && *t == started) {
            inflight.remove(i);
        }
        drop(inflight);
        let _ = tx.send(r);
    });
    if let Err(e) = spawned {
        IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner()).retain(|(p, t)| !(p == path && *t == started));
        return Err(format!("thread: {e}"));
    }
    rx.recv_timeout(timeout).map_err(|_| {
        eprintln!("accès à {} : pas de réponse après {} s", path.display(), timeout.as_secs());
        not_responding()
    })
}

/// Métadonnées rapides (sans lecture du contenu) pour la surveillance périodique.
/// `None` si le fichier est absent ou ne répond pas.
pub fn quick_stat(path: &Path) -> Option<(u64, Option<SystemTime>)> {
    with_timeout(path, STAT_TIMEOUT, |p| fs::metadata(p).ok().map(|m| (m.len(), m.modified().ok())))
        .ok()
        .flatten()
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
    /// L'entrée a un code à usage unique (TOTP).
    pub has_totp: bool,
    /// Période du code en secondes (0 sans TOTP).
    pub totp_period: u64,
    /// URL secondaires (`KP2A_URL`, `KP2A_URL_1`… de Keepass2Android et KeePassXC).
    #[serde(skip)]
    pub extra_urls: Vec<String>,
}

/// URL secondaires d'une entrée : champs `KP2A_URL`, `KP2A_URL_1`… (Keepass2Android, « URL
/// supplémentaires » de KeePassXC), champs nommés comme une URL (« URL2 », « url_1 »), et champs
/// personnalisés dont la valeur est un lien http(s):// ou androidapp://.
fn extra_urls(e: &keepass::db::EntryRef<'_>) -> Vec<String> {
    const STANDARD: [&str; 6] = ["title", "username", "password", "url", "notes", "otp"];
    let url_name = |k: &str| {
        let k = k.to_ascii_lowercase();
        let rest = k.strip_prefix("kp2a_").unwrap_or(&k);
        rest.strip_prefix("url").is_some_and(|n| n.trim_start_matches([' ', '_', '-']).bytes().all(|b| b.is_ascii_digit()))
    };
    let link_value = |v: &str| {
        let v = v.trim().to_ascii_lowercase();
        v.starts_with("https://") || v.starts_with("http://") || v.starts_with("androidapp://")
    };
    let mut fields: Vec<(&String, String)> = e
        .fields
        .keys()
        .filter(|k| !STANDARD.contains(&k.to_ascii_lowercase().as_str()) && k.as_str() != LINK_FIELD)
        .filter_map(|k| e.get(k).map(|v| (k, v.trim().to_string())))
        .filter(|(k, v)| !v.is_empty() && !v.contains('\n') && (url_name(k) || link_value(v)))
        .collect();
    fields.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(b.0)));
    fields.into_iter().map(|(_, v)| v).collect()
}

/// URL principale puis URL secondaires.
fn all_urls(e: &keepass::db::EntryRef<'_>) -> Vec<String> {
    let mut v = vec![e.get_url().unwrap_or("").trim().to_string()];
    v.extend(extra_urls(e));
    v.retain(|u| !u.is_empty());
    v
}

/// Lit le fichier et calcule son empreinte, avec le délai [`READ_TIMEOUT`].
pub fn read_file(path: &Path) -> Result<(Zeroizing<Vec<u8>>, Fingerprint), String> {
    with_timeout(path, READ_TIMEOUT, |path| {
        let bytes = Zeroizing::new(fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?);
        let meta = fs::metadata(path).map_err(|e| format!("stat : {e}"))?;
        let fp = Fingerprint::of_bytes(&bytes, &meta);
        Ok((bytes, fp))
    })?
}

pub fn open_err(e: keepass::db::DatabaseOpenError) -> String {
    let s = e.to_string();
    if s.to_lowercase().contains("key") || s.to_lowercase().contains("hmac") {
        crate::i18n::tr("incorrect master password or key file")
    } else {
        format!("cannot open the database: {s}")
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
        self.reload_from(raw, fp)
    }

    /// Recharge à partir d'un contenu lu par [`read_file`] (hors verrou). Ok(true) si la base a changé.
    pub fn reload_from(&mut self, raw: Zeroizing<Vec<u8>>, fp: Fingerprint) -> Result<bool, String> {
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
        self.live_entries().map(|e| summary_of(&e)).collect()
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
                let urls: Vec<String> = all_urls(&e).iter().map(|u| u.to_lowercase()).collect();
                let url_match = urls.iter().any(|u| {
                    let u = u.trim_end_matches('/');
                    u == origin.trim_end_matches('/') || u.strip_prefix("androidapp://") == Some(app)
                });
                // Champs « AndroidApp… » de KeePassDX / Keepass2Android : androidapp://paquet
                let field_match = e.fields.iter().any(|(k, v)| {
                    k.to_lowercase().starts_with("androidapp")
                        && v.get().to_lowercase().trim_start_matches("androidapp://") == app
                });
                let title = e.get_title().unwrap_or("").to_lowercase();
                // Segments significatifs du nom de paquet : com.netflix.mediaclient → « netflix ».
                let tokens = app_tokens(app);
                let url_cores: Vec<String> = urls
                    .iter()
                    .filter_map(|u| host_of(u))
                    .map(|h| registrable(&h).split('.').next().unwrap_or("").to_string())
                    .filter(|c| !c.is_empty())
                    .collect();
                let score = if url_match || field_match {
                    3
                } else if tokens.iter().any(|t| url_cores.contains(t)) {
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
            let title = e.get_title().unwrap_or("").to_lowercase();
            let by_url = all_urls(&e)
                .iter()
                .filter_map(|u| host_of(u))
                .map(|h| if h == host { 3 } else if registrable(&h) == domain { 2 } else { 0 })
                .max()
                .unwrap_or(0);
            let score = if by_url > 0 {
                by_url
            } else if core.len() >= 4 && title.contains(&core) {
                1
            } else {
                0
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
        let e = self.find(id).ok_or("entry not found")?;
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

    /// Résumé d'une entrée (titre, identifiant, URL…), sans secret.
    pub fn summary(&self, id: &str) -> Option<EntrySummary> {
        self.find(id).map(|e| summary_of(&e))
    }

    /// Entrée de cette base (base des codes) correspondant à une entrée de la base des mots de
    /// passe : lien posé par le clavier (champ `KeePassKbd-Link`), sinon même site (URL, titre
    /// ou émetteur du lien otpauth, croisés) et même compte (identifiant, ou compte du lien
    /// otpauth ; absent d'un côté = accepté). `with_totp` : seulement les entrées qui ont un code.
    pub fn counterpart(&self, src: &EntrySummary, with_totp: bool) -> Option<String> {
        let has = |e: &keepass::db::EntryRef<'_>| !with_totp || crate::totp::Spec::from_fields(|k| e.get(k)).is_some();
        let candidates: Vec<_> = self.live_entries().filter(|e| has(e)).collect();
        if let Some(e) = candidates.iter().find(|e| e.get(LINK_FIELD).map(str::trim) == Some(src.id.as_str())) {
            return Some(e.id().to_string());
        }
        let src_keys = site_keys(
            [src.url.as_str(), src.title.as_str()].into_iter().chain(src.extra_urls.iter().map(String::as_str)),
        );
        if src_keys.is_empty() {
            return None;
        }
        let described = |e: &keepass::db::EntryRef<'_>| e.get("otp").and_then(crate::totp::describe);
        let matching: Vec<_> = candidates
            .iter()
            .filter(|e| {
                let d = described(e);
                let issuer = d.as_ref().map(|d| d.issuer.clone()).unwrap_or_default();
                let urls = all_urls(e);
                let keys = site_keys(
                    urls.iter().map(String::as_str).chain([e.get_title().unwrap_or(""), issuer.as_str()]),
                );
                keys.iter().any(|k| src_keys.contains(k))
            })
            .collect();
        // Même compte d'abord, puis compte inconnu ; jamais un autre compte.
        let src_user = src.username.trim();
        let verdict = |e: &&keepass::db::EntryRef<'_>| entry_account(e, src_user);
        matching
            .iter()
            .find(|e| verdict(e) == Some(true))
            .or_else(|| matching.iter().find(|e| verdict(e).is_none()))
            .map(|e| e.id().to_string())
    }

    /// Code TOTP actuel d'une entrée : (code, secondes restantes, période).
    pub fn totp(&self, id: &str) -> Result<(String, u64, u64), String> {
        let e = self.find(id).ok_or("entry not found")?;
        let spec = crate::totp::Spec::from_fields(|k| e.get(k)).ok_or("no one-time code for this entry")?;
        let (code, remaining) = spec.code_now();
        Ok((code, remaining, spec.period))
    }

    /// Vérifie que la bibliothèque réécrit la base actuelle sans perdre d'éléments XML.
    pub fn check_fidelity(&mut self) -> Result<(), String> {
        if self.fidelity_ok_for == Some(self.fingerprint.sha256) {
            return Ok(());
        }
        check_fidelity(&self.raw, &self.db, &self.creds.key())?;
        self.fidelity_ok_for = Some(self.fingerprint.sha256);
        Ok(())
    }

    /// Copie de l'état courant pour préparer une écriture hors verrou (les dérivations
    /// de clé Argon2 peuvent prendre plusieurs secondes chacune).
    pub fn snapshot(&mut self) -> Result<Snapshot, String> {
        self.reload_if_changed()?;
        Ok(Snapshot {
            db: self.db.clone(),
            raw: self.raw.clone(),
            sha256: self.fingerprint.sha256,
            key: self.creds.key(),
            fidelity_ok: self.fidelity_ok_for == Some(self.fingerprint.sha256),
        })
    }

    /// Note le résultat d'un test de fidélité fait hors verrou, si la base n'a pas changé entre-temps.
    pub fn mark_fidelity_ok(&mut self, sha256: [u8; 32]) {
        if self.fingerprint.sha256 == sha256 {
            self.fidelity_ok_for = Some(sha256);
        }
    }

    /// Écrit une base préparée par [`prepare_add`] : sauvegarde, contrôle de concurrence,
    /// écriture dans un temporaire relu puis renommage atomique.
    pub fn commit(&mut self, snap: &Snapshot, prepared: Prepared, backup_dir: &Path, backups_keep: usize) -> Result<String, String> {
        if self.fingerprint.sha256 != snap.sha256 {
            return Err(crate::i18n::tr("the database was reloaded during the save. Try again."));
        }
        let (_, now_fp) = read_file(&self.path)?;
        if now_fp.sha256 != snap.sha256 {
            return Err(crate::i18n::tr("the database was modified elsewhere during the save. Try again."));
        }
        backup(&self.raw, backup_dir, backups_keep)?;
        let out = &prepared.bytes;
        let tmp = self.path.with_file_name(format!(
            ".{}.keepass-kbd.tmp",
            self.path.file_name().and_then(|s| s.to_str()).unwrap_or("db")
        ));
        {
            let mut f = fs::File::create(&tmp).map_err(|e| format!("creating the temporary file: {e}"))?;
            f.write_all(out).map_err(|e| format!("writing: {e}"))?;
            f.sync_all().map_err(|e| format!("syncing: {e}"))?;
        }
        let written = fs::read(&tmp).map_err(|e| format!("re-reading the temporary file: {e}"))?;
        if written != **out {
            let _ = fs::remove_file(&tmp);
            return Err("the re-read temporary file does not match. Nothing was replaced.".into());
        }
        fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp);
            format!("replacing the file: {e}")
        })?;
        let (raw, fp) = read_file(&self.path)?;
        if *raw != **out {
            return Err("the final file differs from what was written (backup available).".into());
        }
        self.db = prepared.db;
        self.raw = raw;
        self.fingerprint = fp;
        self.fidelity_ok_for = Some(self.fingerprint.sha256);
        Ok(prepared.id)
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
    let totp_period = crate::totp::Spec::from_fields(|k| e.get(k)).map_or(0, |s| s.period);
    EntrySummary {
        id: e.id().to_string(),
        title: e.get_title().unwrap_or("").to_string(),
        username: e.get_username().unwrap_or("").to_string(),
        url: e.get_url().unwrap_or("").to_string(),
        group: e.parent().name.clone(),
        has_totp: totp_period > 0,
        totp_period,
        extra_urls: extra_urls(e),
    }
}

/// Clés de site d'une entrée, à partir de son URL, de son titre ou de l'émetteur d'un code :
/// nom du domaine sans extension (« facebook » pour https://m.facebook.com) et texte réduit aux
/// lettres et chiffres (« facebook » pour « Facebook », « comptegh » pour « Compte GH »).
fn site_keys<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut keys = Vec::new();
    for t in texts {
        let t = t.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(host) = host_of(t) {
            let domain = registrable(&host);
            keys.push(domain.split('.').next().unwrap_or("").to_string());
        }
        keys.push(t.to_lowercase().chars().filter(|c| c.is_alphanumeric()).collect());
    }
    keys.retain(|k| k.chars().count() >= 2);
    keys.sort();
    keys.dedup();
    keys
}

/// Compte d'une entrée de la base des codes comparé à l'identifiant `src_user` : d'après son
/// identifiant s'il est rempli ; sinon d'après le compte du lien otpauth, qui ne fait que
/// confirmer (nom ou téléphone ≠ e-mail : inconnu), sauf deux adresses e-mail différentes.
fn entry_account(e: &keepass::db::EntryRef<'_>, src_user: &str) -> Option<bool> {
    let u = e.get_username().unwrap_or("").trim();
    if !u.is_empty() {
        return same_account(u, src_user);
    }
    let account = e.get("otp").and_then(crate::totp::describe).map(|d| d.account).unwrap_or_default();
    match same_account(&account, src_user) {
        Some(true) => Some(true),
        Some(false) if account.contains('@') && src_user.contains('@') => Some(false),
        _ => None,
    }
}

/// Même compte ? Some(true) : identique (casse ignorée ; « boris@x.fr » et « boris » aussi),
/// Some(false) : autre compte, None : identifiant absent d'un côté.
fn same_account(a: &str, b: &str) -> Option<bool> {
    let (a, b) = (a.trim().to_lowercase(), b.trim().to_lowercase());
    if a.is_empty() || b.is_empty() {
        return None;
    }
    let local = |s: &str| s.split('@').next().unwrap_or("").to_string();
    Some(a == b || (!a.contains('@') && local(&b) == a) || (!b.contains('@') && local(&a) == b))
}


/// Hôte d'une URL en minuscules (sans schéma, port, chemin ni « www. »). Accepte une URL sans schéma.
pub fn host_of(url: &str) -> Option<String> {
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
pub fn registrable(host: &str) -> String {
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

pub struct Snapshot {
    pub db: Database,
    pub raw: Zeroizing<Vec<u8>>,
    pub sha256: [u8; 32],
    pub key: DatabaseKey,
    pub fidelity_ok: bool,
}

pub struct Prepared {
    pub db: Database,
    pub bytes: Zeroizing<Vec<u8>>,
    pub id: String,
}

/// Différences de balises sans effet, admises lors du test de fidélité.
fn benign_difference(name: &str, before: usize, resaved_xml: &[u8], version_kdbx4: bool) -> bool {
    match name {
        // Reliquat KDBX 3 : en KDBX 4, l'en-tête est protégé par HMAC et cet élément est ignoré.
        "HeaderHash" => version_kdbx4,
        // Valeur par défaut (vrai) rendue explicite ; admis seulement si aucune valeur « False » n'apparaît.
        "QualityCheck" => before == 0 && !contains(resaved_xml, b"<QualityCheck>False"),
        _ => false,
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Test de fidélité : réécrire la base sans modification ne doit rien perdre.
pub fn check_fidelity(raw: &[u8], db: &Database, key: &DatabaseKey) -> Result<(), String> {
    let original_xml = Zeroizing::new(Database::get_xml(&mut &raw[..], key.clone()).map_err(open_err)?);
    let mut resaved = Zeroizing::new(Vec::new());
    db.save(&mut *resaved, key.clone()).map_err(|e| format!("serialisation: {e}"))?;
    let resaved_xml = Zeroizing::new(Database::get_xml(&mut &resaved[..], key.clone()).map_err(open_err)?);
    let kdbx4 = matches!(db.config.version, keepass::config::DatabaseVersion::KDB4(_));
    let before = tag_histogram(&original_xml);
    let after = tag_histogram(&resaved_xml);
    let diff: Vec<String> = histogram_diff(&before, &after)
        .into_iter()
        .filter(|d| {
            let name = d.split(':').next().unwrap_or("");
            !benign_difference(name, before.get(name).copied().unwrap_or(0), &resaved_xml, kdbx4)
        })
        .collect();
    if !diff.is_empty() {
        return Err(crate::i18n::tr1(
            "rewriting would lose or alter database elements (%1). Write refused.",
            &diff.join(", "),
        ));
    }
    let reparsed = Database::parse(&resaved, key.clone()).map_err(open_err)?;
    if reparsed != *db {
        return Err("the database re-read after rewriting differs from the original. Write refused.".into());
    }
    Ok(())
}

/// Prépare l'ajout d'une entrée hors verrou : test de fidélité si nécessaire, sérialisation,
/// relecture et comparaison complète.
pub fn prepare_add(
    snap: &Snapshot,
    group_path: &str,
    title: &str,
    username: &str,
    password: &str,
    url: &str,
) -> Result<Prepared, String> {
    if !snap.fidelity_ok {
        check_fidelity(&snap.raw, &snap.db, &snap.key)?;
    }
    let mut modified = snap.db.clone();
    let group = ensure_group(&mut modified, group_path)?;
    let id = {
        let mut g = modified.group_mut(group).ok_or("target group not found")?;
        let mut e = g.add_entry();
        e.set_unprotected("Title", title);
        e.set_unprotected("UserName", username);
        e.set_protected("Password", password);
        e.set_unprotected("URL", url);
        e.set_unprotected("Notes", "");
        e.id()
    };
    serialise(modified, &snap.key, id.to_string())
}

/// Champ des entrées de la base des codes : identifiant de l'entrée liée dans la base des mots de passe.
pub const LINK_FIELD: &str = "KeePassKbd-Link";

/// Réglages de dérivation de clé des bases créées ici : Argon2id, 64 Mio, comme KeePassXC.
fn new_database_config() -> keepass::config::DatabaseConfig {
    let mut cfg = keepass::config::DatabaseConfig::default();
    cfg.kdf_config = keepass::config::KdfConfig::Argon2id {
        iterations: NEW_DB_ITERATIONS,
        memory: 64 * 1024 * 1024,
        parallelism: 4,
        version: argon2::Version::Version13,
    };
    cfg
}
/// Passes Argon2id : environ une seconde de déverrouillage sur un téléphone récent.
const NEW_DB_ITERATIONS: u64 = 10;

/// Crée une base vide (KDBX 4) protégée par `creds` ; refuse d'écraser un fichier existant.
pub fn create_database(path: &Path, creds: &Credentials, name: &str) -> Result<(), String> {
    if creds.password.is_empty() && creds.keyfile.is_none() {
        return Err(crate::i18n::tr("a password or a key file is required"));
    }
    let mut db = Database::with_config(new_database_config());
    db.meta.database_name = Some(name.to_string());
    db.root_mut().name = name.to_string();
    let mut out = Zeroizing::new(Vec::new());
    db.save(&mut *out, creds.key()).map_err(|e| format!("serialisation: {e}"))?;
    Database::parse(&out, creds.key()).map_err(open_err)?;
    use crate::keyfile::PrivateMode;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_private()
        .open(path)
        .map_err(|e| crate::i18n::tr1("cannot create the file (%1)", &format!("{}: {e}", path.display())))?;
    f.write_all(&out).and_then(|_| f.sync_all()).map_err(|e| e.to_string())
}

/// Prépare la création, dans la base des codes, de l'entrée qui porte le code d'une entrée
/// de la base des mots de passe : titre, identifiant et URL recopiés, aucun mot de passe,
/// champ `otp` et lien vers l'entrée d'origine.
pub fn prepare_add_otp_entry(
    snap: &Snapshot,
    group_path: &str,
    src: &EntrySummary,
    uri: &str,
) -> Result<Prepared, String> {
    if !snap.fidelity_ok {
        check_fidelity(&snap.raw, &snap.db, &snap.key)?;
    }
    let mut modified = snap.db.clone();
    let group = ensure_group(&mut modified, group_path)?;
    let id = {
        let mut g = modified.group_mut(group).ok_or("target group not found")?;
        let mut e = g.add_entry();
        e.set_unprotected("Title", src.title.as_str());
        e.set_unprotected("UserName", src.username.as_str());
        e.set_protected("Password", "");
        e.set_unprotected("URL", src.url.as_str());
        e.set_unprotected("Notes", "");
        e.set_protected("otp", uri);
        e.set_unprotected(LINK_FIELD, src.id.as_str());
        e.id()
    };
    serialise(modified, &snap.key, id.to_string())
}

/// Prépare l'ajout (ou le remplacement) du code à usage unique d'une entrée : champ protégé
/// `otp` contenant l'URI otpauth. L'état précédent de l'entrée rejoint son historique, comme
/// lors d'une modification dans KeePassXC. Les anciens champs TOTP éventuels sont laissés :
/// le champ `otp` est lu en premier.
pub fn prepare_set_otp(snap: &Snapshot, id: &str, uri: &str, link: Option<&str>) -> Result<Prepared, String> {
    if !snap.fidelity_ok {
        check_fidelity(&snap.raw, &snap.db, &snap.key)?;
    }
    let uuid = uuid::Uuid::parse_str(id).map_err(|_| crate::i18n::tr("entry not found"))?;
    let mut modified = snap.db.clone();
    {
        let mut e = modified.entry_mut(EntryId::from(uuid)).ok_or_else(|| crate::i18n::tr("entry not found"))?;
        let mut tracked = e.track_changes();
        tracked.set_protected("otp", uri);
        if let Some(link) = link {
            tracked.set_unprotected(LINK_FIELD, link);
        }
    }
    serialise(modified, &snap.key, id.to_string())
}

/// Sérialise une base modifiée, la relit et la compare à l'original en mémoire.
fn serialise(modified: Database, key: &DatabaseKey, id: String) -> Result<Prepared, String> {
    let mut out = Zeroizing::new(Vec::new());
    modified.save(&mut *out, key.clone()).map_err(|e| format!("serialisation: {e}"))?;
    let reparsed = Database::parse(&out, key.clone()).map_err(open_err)?;
    if reparsed != modified {
        return Err("in-memory verification after writing failed. Nothing was written.".into());
    }
    Ok(Prepared { db: modified, bytes: out, id })
}

/// Groupe de destination (« Dossier/Sous-dossier »), créé s'il n'existe pas. "" = racine.
fn ensure_group(db: &mut Database, path: &str) -> Result<GroupId, String> {
    let parts: Vec<&str> = path.split('/').map(str::trim).filter(|s| !s.is_empty()).collect();
    let mut current = db.root().id();
    for part in parts {
        let existing = db
            .group(current)
            .and_then(|g| g.groups().find(|c| c.name == part).map(|c| c.id()));
        current = match existing {
            Some(id) => id,
            None => {
                let mut parent = db.group_mut(current).ok_or("parent group not found")?;
                let mut g = parent.add_group();
                g.name = part.to_string();
                g.id()
            }
        };
    }
    Ok(current)
}

/// Chemins de tous les groupes (hors corbeille), triés ; "" désigne la racine.
pub fn group_paths(db: &Database) -> Vec<String> {
    fn walk(g: keepass::db::GroupRef<'_>, prefix: &str, bin: Option<GroupId>, out: &mut Vec<String>) {
        for c in g.groups() {
            if Some(c.id()) == bin {
                continue;
            }
            let path = if prefix.is_empty() { c.name.clone() } else { format!("{prefix}/{}", c.name) };
            out.push(path.clone());
            walk(c, &path, bin, out);
        }
    }
    let mut out = vec![String::new()];
    let bin = db.recycle_bin().map(|g| g.id());
    walk(db.root(), "", bin, &mut out);
    out[1..].sort_by_key(|p| p.to_lowercase());
    out
}

fn backup(raw: &[u8], dir: &Path, keep: usize) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("backup folder: {e}"))?;
    let name = chrono::Local::now().format("%Y%m%d-%H%M%S%.3f.kdbx").to_string();
    fs::write(dir.join(name), raw).map_err(|e| format!("backup: {e}"))?;
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("backups: {e}"))?
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
    #[test]
    fn with_timeout_gives_up_and_does_not_pile_up_threads() {
        let path = Path::new("/keepass-kbd-test/slow");
        let short = Duration::from_millis(100);
        // Accès qui ne répond pas dans le délai.
        let t = Instant::now();
        let r = with_timeout(path, short, |_| std::thread::sleep(Duration::from_millis(600)));
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_millis(400));
        // Tant que le premier est bloqué au-delà du délai : échec immédiat, sans nouveau fil.
        std::thread::sleep(Duration::from_millis(50));
        let t = Instant::now();
        assert!(with_timeout(path, short, |_| 1).is_err());
        assert!(t.elapsed() < Duration::from_millis(50));
        // Un autre fichier n'est pas concerné.
        assert_eq!(with_timeout(Path::new("/keepass-kbd-test/other"), short, |_| 2), Ok(2));
        // Une fois l'accès bloqué terminé, le fichier redevient utilisable.
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(with_timeout(path, short, |_| 3), Ok(3));
    }

    use super::*;

    #[test]
    fn otp_is_added_with_history() {
        let key = DatabaseKey::new().with_password("test");
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "Site");
            e.set_unprotected("UserName", "boris");
            e.set_protected("Password", "secret");
            e.id()
        };
        let mut raw = Zeroizing::new(Vec::new());
        db.save(&mut *raw, key.clone()).unwrap();
        let db = Database::parse(&raw, key.clone()).unwrap();
        let snap = Snapshot { db, raw, sha256: [0; 32], key: key.clone(), fidelity_ok: false };
        let uri = "otpauth://totp/Site:boris?secret=JBSWY3DPEHPK3PXP&issuer=Site";
        let prepared = prepare_set_otp(&snap, &id.to_string(), uri, None).unwrap();
        let reread = Database::parse(&prepared.bytes, key).unwrap();
        let e = reread.entry(id).unwrap();
        assert_eq!(e.get("otp"), Some(uri));
        assert_eq!(e.get("Password"), Some("secret"));
        let history = e.history.as_ref().unwrap();
        assert_eq!(history.get_entries().len(), 1);
        assert_eq!(history.get_entries()[0].get("otp"), None);
        assert!(prepare_set_otp(&snap, "00000000-0000-0000-0000-000000000000", uri, None).is_err());
    }

    fn summary(id: &str, title: &str, user: &str, url: &str) -> EntrySummary {
        EntrySummary {
            id: id.into(),
            title: title.into(),
            username: user.into(),
            url: url.into(),
            group: String::new(),
            has_totp: false,
            totp_period: 0,
            extra_urls: Vec::new(),
        }
    }

    #[test]
    fn separate_otp_database() {
        let dir = std::env::temp_dir().join(format!("keepass-kbd-otpdb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("codes.kdbx");
        let creds = || Credentials { password: Zeroizing::new("otp".into()), keyfile: None };
        create_database(&path, &creds(), "Codes").unwrap();
        assert!(create_database(&path, &creds(), "Codes").is_err(), "ne doit pas écraser");
        let empty = Credentials { password: Zeroizing::new(String::new()), keyfile: None };
        assert!(create_database(&dir.join("x.kdbx"), &empty, "x").is_err());

        let mut v = Vault::open(&path, creds()).unwrap();
        assert!(matches!(v.db.config.kdf_config, keepass::config::KdfConfig::Argon2id { .. }));
        let uri = "otpauth://totp/GitHub:boris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let github = summary("11111111-1111-1111-1111-111111111111", "GitHub", "boris", "https://github.com/login");
        // Ajout d'une entrée liée, écrite dans le fichier.
        let snap = v.snapshot().unwrap();
        let p = prepare_add_otp_entry(&snap, "", &github, uri).unwrap();
        let new_id = p.id.clone();
        v.commit(&snap, p, &dir.join("backups"), 3).unwrap();
        let e = v.db.entry(EntryId::from(uuid::Uuid::parse_str(&new_id).unwrap())).unwrap();
        assert_eq!(e.get(LINK_FIELD), Some(github.id.as_str()));
        assert_eq!(e.get("Password"), Some(""));
        // Lien, puis même site, puis même titre ; jamais un autre compte du même site.
        assert_eq!(v.counterpart(&github, true), Some(new_id.clone()));
        let same_site = summary("22222222-2222-2222-2222-222222222222", "Compte GH", "boris", "https://www.github.com/");
        assert_eq!(v.counterpart(&same_site, true), Some(new_id.clone()));
        let same_title = summary("33333333-3333-3333-3333-333333333333", "github", "", "");
        assert_eq!(v.counterpart(&same_title, true), Some(new_id.clone()));
        let other_user = summary("44444444-4444-4444-4444-444444444444", "GitHub", "alice", "https://github.com");
        assert_eq!(v.counterpart(&other_user, true), None);
        let other_site = summary("55555555-5555-5555-5555-555555555555", "Banque", "boris", "https://banque.example");
        assert_eq!(v.counterpart(&other_site, true), None);
        // Entrée créée ailleurs : titre seul, pas d'URL ; compte lu dans le lien otpauth.
        let snap = v.snapshot().unwrap();
        let fb_src = summary("66666666-6666-6666-6666-666666666666", "Facebook", "", "");
        let p = prepare_add_otp_entry(&snap, "", &fb_src, "otpauth://totp/Facebook:boris%40mail.fr?secret=JBSWY3DPEHPK3PXP&issuer=Facebook").unwrap();
        let fb_id = p.id.clone();
        v.commit(&snap, p, &dir.join("backups"), 3).unwrap();
        // Retirer le lien : on simule une entrée importée d'une autre application.
        v.db.entry_mut(EntryId::from(uuid::Uuid::parse_str(&fb_id).unwrap())).unwrap().set_unprotected(LINK_FIELD, "");
        let fb = summary("77777777-7777-7777-7777-777777777777", "facebook.com", "boris@mail.fr", "https://www.facebook.com/login");
        assert_eq!(v.counterpart(&fb, true), Some(fb_id.clone()));
        let fb_short = summary("88888888-8888-8888-8888-888888888888", "FB", "boris", "https://m.facebook.com");
        assert_eq!(v.counterpart(&fb_short, true), Some(fb_id.clone()));
        let fb_other = summary("99999999-9999-9999-9999-999999999999", "Facebook", "alice@mail.fr", "https://facebook.com");
        assert_eq!(v.counterpart(&fb_other, true), None);
        // Sans identifiant, compte otpauth = un nom : ne contredit pas une adresse e-mail.
        let snap = v.snapshot().unwrap();
        let li_src = summary("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "LinkedIn", "", "");
        let p = prepare_add_otp_entry(&snap, "", &li_src, "otpauth://totp/LinkedIn:Boris%20S?secret=JBSWY3DPEHPK3PXP&issuer=LinkedIn").unwrap();
        let li_id = p.id.clone();
        v.commit(&snap, p, &dir.join("backups"), 3).unwrap();
        v.db.entry_mut(EntryId::from(uuid::Uuid::parse_str(&li_id).unwrap())).unwrap().set_unprotected(LINK_FIELD, "");
        let li = summary("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "LinkedIn", "boris@mail.fr", "https://www.linkedin.com");
        assert_eq!(v.counterpart(&li, true), Some(li_id.clone()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn secondary_urls() {
        let dir = std::env::temp_dir().join(format!("keepass-kbd-kp2a-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("m.kdbx");
        let creds = || Credentials { password: Zeroizing::new("m".into()), keyfile: None };
        create_database(&path, &creds(), "M").unwrap();
        let mut v = Vault::open(&path, creds()).unwrap();
        let id = {
            let mut root = v.db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "Compte perso");
            e.set_unprotected("UserName", "boris@mail.fr");
            e.set_unprotected("URL", "https://exemple.org");
            e.set_unprotected("KP2A_URL", "https://accounts.google.com");
            e.set_unprotected("KP2A_URL_1", "androidapp://com.google.android.gm");
            e.set_unprotected("KP2A_URLX", "ignore.example");
            e.set_unprotected("URL2", "www.amazon.ca");
            e.set_unprotected("Page de secours", "https://m.facebook.com");
            e.id().to_string()
        };
        let s = v.summary(&id).unwrap();
        assert_eq!(s.extra_urls, vec![
            "www.amazon.ca", "https://accounts.google.com", "androidapp://com.google.android.gm", "https://m.facebook.com"
        ]);
        let web = v.suggestions("https://accounts.google.com/signin");
        assert!(web.iter().any(|(score, e)| *score == 3 && e.id == id));
        assert!(v.suggestions("https://mail.google.com").iter().any(|(score, e)| *score == 2 && e.id == id));
        assert!(v.suggestions("app://com.google.android.gm").iter().any(|(score, e)| *score == 3 && e.id == id));
        assert!(v.suggestions("https://ignore.example").is_empty());
        assert!(v.suggestions("https://www.amazon.ca/ap/signin").iter().any(|(score, e)| *score == 3 && e.id == id));
        assert!(v.suggestions("https://m.facebook.com").iter().any(|(score, e)| *score == 3 && e.id == id));

        // Base des codes : entrée « Google » sans identifiant, retrouvée grâce à l'URL secondaire.
        let otp_path = dir.join("o.kdbx");
        create_database(&otp_path, &creds(), "O").unwrap();
        let mut o = Vault::open(&otp_path, creds()).unwrap();
        let otp_id = {
            let mut root = o.db.root_mut();
            let mut e = root.add_entry();
            e.set_unprotected("Title", "Google");
            e.set_protected("otp", "otpauth://totp/Google:Boris?secret=JBSWY3DPEHPK3PXP&issuer=Google");
            e.id().to_string()
        };
        assert_eq!(o.counterpart(&s, true), Some(otp_id));
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
    fn groups_are_created_and_listed() {
        let mut db = Database::new();
        let a = ensure_group(&mut db, "keepass-kbd").unwrap();
        assert_eq!(ensure_group(&mut db, "keepass-kbd").unwrap(), a);
        let b = ensure_group(&mut db, "Internet/Banques").unwrap();
        assert_ne!(a, b);
        assert_eq!(ensure_group(&mut db, "").unwrap(), db.root().id());
        assert_eq!(group_paths(&db), vec!["", "Internet", "Internet/Banques", "keepass-kbd"]);
    }

    #[test]
    fn benign_differences() {
        assert!(benign_difference("HeaderHash", 1, b"", true));
        assert!(!benign_difference("HeaderHash", 1, b"", false));
        assert!(benign_difference("QualityCheck", 0, b"<QualityCheck>True</QualityCheck>", true));
        assert!(!benign_difference("QualityCheck", 0, b"<QualityCheck>False</QualityCheck>", true));
        assert!(!benign_difference("QualityCheck", 3, b"", true));
        assert!(!benign_difference("CustomData", 1, b"", true));
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
