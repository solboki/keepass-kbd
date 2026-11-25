//! Service D-Bus de session `org.keepasskbd.Daemon` utilisé par la disposition clavier.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::json;
use zbus::message::Header;
use zbus::{fdo, interface};
use zeroize::Zeroizing;

use crate::config::{data_dir, Config, RELOCK_POLICIES};
use crate::generator;
use crate::i18n::{tr, tr1};
use crate::vault::{quick_stat, Credentials, Vault};

pub const OBJECT_PATH: &str = "/org/keepasskbd/Daemon";
pub const INTERFACE: &str = "org.keepasskbd.Daemon1";

pub struct Inner {
    pub cfg: Config,
    pub cfg_path: PathBuf,
    pub vault: Option<Vault>,
    pub unlocked_at: Option<Instant>,
    pub saving: bool,
    pub last_stat: Option<(u64, Option<SystemTime>)>,
    /// Base séparée des codes à usage unique (si configurée et déverrouillée).
    pub otp_vault: Option<Vault>,
    pub otp_unlocked_at: Option<Instant>,
    pub otp_last_stat: Option<(u64, Option<SystemTime>)>,
    pub message: String,
    pub usage: HashMap<String, u64>,
}

pub type Shared = Arc<Mutex<Inner>>;

fn usage_path() -> PathBuf {
    data_dir().join("usage.json")
}

pub fn load_usage() -> HashMap<String, u64> {
    std::fs::read_to_string(usage_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_usage(u: &HashMap<String, u64>) {
    let _ = std::fs::create_dir_all(data_dir());
    let _ = std::fs::write(usage_path(), serde_json::to_string(u).unwrap_or_default());
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Minuscules sans accents, pour la recherche.
fn fold(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .map(|c| match c {
            'à' | 'â' | 'ä' | 'á' | 'ã' | 'å' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'î' | 'ï' | 'í' | 'ì' => 'i',
            'ô' | 'ö' | 'ó' | 'ò' | 'õ' => 'o',
            'ù' | 'û' | 'ü' | 'ú' => 'u',
            'ç' => 'c',
            'ÿ' => 'y',
            'ñ' => 'n',
            c => c,
        })
        .collect()
}

impl Inner {
    pub fn state(&self) -> &'static str {
        if !self.cfg.database_enabled {
            "disabled"
        } else if self.vault.is_some() {
            "unlocked"
        } else if self.cfg.database.as_os_str().is_empty() || !file_present(&self.cfg.database) {
            "missing"
        } else {
            "locked"
        }
    }

    /// Une base séparée est choisie pour les codes à usage unique.
    pub fn otp_configured(&self) -> bool {
        !self.cfg.otp_database.as_os_str().is_empty()
    }

    /// État de la base des codes : none (codes dans la base principale), unlocked, missing, locked.
    pub fn otp_state(&self) -> &'static str {
        if !self.otp_configured() {
            "none"
        } else if self.otp_vault.is_some() {
            "unlocked"
        } else if !file_present(&self.cfg.otp_database) {
            "missing"
        } else {
            "locked"
        }
    }

    /// Base des codes ouverte par le seul fichier clé.
    pub fn otp_keyfile_only(&self) -> bool {
        self.cfg.otp_keyfile_only && self.cfg.otp_keyfile.is_some()
    }

    pub fn status_json(&self) -> String {
        json!({
            "state": self.state(),
            "database": self.cfg.database.file_name().map(|s| s.to_string_lossy().to_string()),
            "entries": self.vault.as_ref().map(|v| v.entry_count()),
            "message": self.message,
            "totp_enabled": self.cfg.totp_enabled,
            "otp_state": self.otp_state(),
            "otp_keyfile_only": self.otp_keyfile_only(),
        })
        .to_string()
    }

    /// Verrouille les deux bases.
    pub fn lock(&mut self, reason: &str) {
        self.unlocked_at = None;
        let otp = self.otp_vault.take().is_some();
        self.otp_unlocked_at = None;
        if self.vault.take().is_some() || otp {
            self.message = reason.to_string();
        }
    }

    /// Verrouille la base des codes seule.
    pub fn lock_otp(&mut self) {
        self.otp_vault = None;
        self.otp_unlocked_at = None;
        self.otp_last_stat = None;
    }

    pub fn vault_of(&mut self, which: Which) -> Option<&mut Vault> {
        match which {
            Which::Main => self.vault.as_mut(),
            Which::Otp => self.otp_vault.as_mut(),
        }
    }

    /// Avec une base des codes déverrouillée, marque les entrées qui y ont un code.
    pub fn enrich(&self, items: &mut [crate::vault::EntrySummary]) {
        let Some(o) = &self.otp_vault else { return };
        for s in items.iter_mut().filter(|s| !s.has_totp) {
            if let Some(period) = o.counterpart(s, true).and_then(|id| o.totp(&id).ok()).map(|t| t.2) {
                s.has_totp = true;
                s.totp_period = period;
            }
        }
    }
}

/// L'une des deux bases : mots de passe, ou codes à usage unique.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Which {
    Main,
    Otp,
}

impl Which {
    fn backup_dir(self) -> PathBuf {
        data_dir().join(match self {
            Which::Main => "backups",
            Which::Otp => "backups-otp",
        })
    }
    fn path(self, cfg: &Config) -> PathBuf {
        match self {
            Which::Main => cfg.database.clone(),
            Which::Otp => cfg.otp_database.clone(),
        }
    }
}

/// Contenu d'un dossier pour les sélecteurs de fichiers des Paramètres (voir `ListFiles`).
/// Dossier par défaut : celui de la base des mots de passe, sinon le dossier personnel.
fn list_files_json(path: &str, kind: &str, current_db: &std::path::Path) -> String {
    let home = crate::config::home();
    let mut dir = if path.is_empty() {
        current_db.parent().filter(|p| p.is_dir()).map(|p| p.to_path_buf()).unwrap_or_else(|| home.clone())
    } else {
        PathBuf::from(path.trim_start_matches("file://"))
    };
    if !dir.is_dir() {
        dir = home.clone();
    }
    let mut dirs = Vec::new();
    let mut files = Vec::new();
    let read = std::fs::read_dir(&dir);
    let error = read.as_ref().err().map(|e| e.to_string());
    if let Ok(rd) = read {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            let p = e.path();
            if p.is_dir() {
                dirs.push(name);
            } else if match kind {
                "dir" => false,
                "key" => p.is_file() && !name.to_lowercase().ends_with(".kdbx"),
                _ => name.to_lowercase().ends_with(".kdbx"),
            } {
                files.push(name);
            }
        }
    }
    dirs.sort_by_key(|n| n.to_lowercase());
    files.sort_by_key(|n| n.to_lowercase());
    let parent = dir.parent().map(|p| p.to_string_lossy().to_string());
    json!({
        "path": dir.to_string_lossy(),
        "parent": parent,
        "home": home.to_string_lossy(),
        "dirs": dirs,
        "files": files,
        "error": error,
    })
    .to_string()
}

/// Le fichier existe. Un fichier qui ne répond pas (montage réseau figé) est considéré comme
/// présent : le déverrouillage dira alors qu'il ne répond pas.
fn file_present(path: &std::path::Path) -> bool {
    crate::vault::with_timeout(path, crate::vault::STAT_TIMEOUT, |p| p.is_file()).unwrap_or(true)
}

/// Fichier clé configuré, lu en mémoire.
fn read_keyfile(path: Option<&PathBuf>) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    path.map(|p| crate::keyfile::read(p)).transpose()
}

/// Le fichier commence par la signature d'une base KeePass 2 (.kdbx).
fn is_kdbx(path: &std::path::Path) -> bool {
    crate::vault::with_timeout(path, crate::vault::READ_TIMEOUT, |path| {
        let mut head = [0u8; 8];
        std::fs::File::open(path)
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
            .is_ok()
            && head == [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5]
    })
    .unwrap_or(false)
}

pub struct Service {
    pub shared: Shared,
    pub allow_any_caller: bool,
}

impl Service {
    /// `settings_ok` : l'application Paramètres est aussi acceptée (réglages, verrouillage),
    /// jamais pour lire la base.
    async fn check_caller(&self, hdr: &Header<'_>, conn: &zbus::Connection, settings_ok: bool) -> fdo::Result<()> {
        if self.allow_any_caller {
            return Ok(());
        }
        let sender = hdr.sender().ok_or_else(|| fdo::Error::AccessDenied("unknown sender".into()))?;
        let dbus = fdo::DBusProxy::new(conn).await?;
        let pid = dbus.get_connection_unix_process_id(sender.clone().into()).await?;
        let (allowed, settings) = {
            let g = self.shared.lock().unwrap();
            (g.cfg.allowed_callers.clone(), g.cfg.settings_callers.clone())
        };
        if let Ok(exe) = std::fs::read_link(format!("/proc/{pid}/exe")) {
            if allowed.iter().any(|a| *a == exe) || (settings_ok && settings.iter().any(|a| *a == exe)) {
                return Ok(());
            }
            eprintln!("appel refusé depuis {}", exe.display());
            return Err(fdo::Error::AccessDenied(format!("caller not allowed: {}", exe.display())));
        }
        // L'application Paramètres tourne avec le groupe effectif « privileged » (binaire setgid) :
        // son exécutable n'est alors pas lisible. Un processus ordinaire ne peut pas obtenir ce
        // groupe ; on l'accepte pour les réglages s'il a été lancé depuis un exécutable autorisé.
        if settings_ok && privileged_settings_process(pid, &settings) {
            return Ok(());
        }
        eprintln!("appel refusé depuis le processus {pid}");
        Err(fdo::Error::AccessDenied("caller process not allowed".into()))
    }
}

fn privileged_gid() -> Option<u32> {
    std::fs::read_to_string("/etc/group").ok()?.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == "privileged").then(|| f.nth(1)?.parse().ok()).flatten()
    })
}

fn privileged_settings_process(pid: u32, settings: &[PathBuf]) -> bool {
    let Some(gid) = privileged_gid() else { return false };
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { return false };
    let egid = status
        .lines()
        .find_map(|l| l.strip_prefix("Gid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|g| g.parse::<u32>().ok());
    if egid != Some(gid) {
        return false;
    }
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else { return false };
    let argv0 = cmdline.split(|b| *b == 0).next().unwrap_or_default();
    let argv0 = std::path::Path::new(std::str::from_utf8(argv0).unwrap_or(""));
    settings.iter().any(|a| a == argv0)
}

/// Consigne une erreur (jamais de secret) dans le journal et dans `errors.log`.
fn log_error(msg: &str) {
    eprintln!("{msg}");
    let _ = std::fs::create_dir_all(data_dir());
    let line = format!("{} {msg}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(data_dir().join("errors.log")) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Icône des notifications : celle du paquet si elle est installée, sinon une icône du thème.
fn notification_icon() -> String {
    const INSTALLED: &str = "/usr/share/keepass-kbd/keepass-kbd.png";
    if std::path::Path::new(INSTALLED).exists() { INSTALLED.into() } else { "icon-lock-information".into() }
}

/// Notification système (bandeau en haut de l'écran sous Sailfish).
fn notify_blocking(conn: &zbus::blocking::Connection, summary: &str, body: &str) {
    use std::collections::HashMap;
    use zbus::zvariant::Value;
    let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
    hints.insert("x-nemo-preview-summary", Value::from(summary));
    hints.insert("x-nemo-preview-body", Value::from(body));
    hints.insert("urgency", Value::U8(1));
    let icon = notification_icon();
    hints.insert("x-nemo-icon", Value::from(icon.as_str()));
    hints.insert("x-nemo-preview-icon", Value::from(icon.as_str()));
    let r = conn.call_method(
        Some("org.freedesktop.Notifications"),
        "/org/freedesktop/Notifications",
        Some("org.freedesktop.Notifications"),
        "Notify",
        &("Clavier KeePass", 0u32, icon.as_str(), summary, body, Vec::<&str>::new(), hints, 5000i32),
    );
    if let Err(e) = r {
        eprintln!("notification impossible : {e}");
    }
}

/// Test de fidélité en arrière-plan (après déverrouillage ou rechargement), pour que
/// l'enregistrement suivant n'ait plus qu'à sérialiser et vérifier.
pub fn spawn_fidelity_check(shared: Shared, which: Which) {
    let snap = {
        let mut g = shared.lock().unwrap();
        match g.vault_of(which).map(|v| v.snapshot()) {
            Some(Ok(s)) if !s.fidelity_ok => s,
            _ => return,
        }
    };
    std::thread::spawn(move || match crate::vault::check_fidelity(&snap.raw, &snap.db, &snap.key) {
        Ok(()) => {
            if let Some(v) = shared.lock().unwrap().vault_of(which) {
                v.mark_fidelity_ok(snap.sha256);
            }
        }
        Err(e) => log_error(&format!("fidelity check: {e}")),
    });
}

fn failed(e: impl Into<String>) -> fdo::Error {
    fdo::Error::Failed(e.into())
}

#[interface(name = "org.keepasskbd.Daemon1")]
impl Service {
    /// Origine (`https://hôte`) de la page ouverte dans le navigateur natif (dernière page visitée
    /// dans un onglet ouvert, voir `browser.rs`) ; chaîne vide si inconnue.
    async fn browser_origin(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let db = crate::browser::sailfish_browser_db();
        Ok(blocking::unblock(move || crate::browser::last_visited_origin(&db)).await.unwrap_or_default())
    }

    async fn status(&self) -> String {
        self.shared.lock().unwrap().status_json()
    }

    async fn unlock(
        &self,
        password: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let password = Zeroizing::new(password);
        let (path, keyfile) = {
            let g = self.shared.lock().unwrap();
            if !g.cfg.database_enabled {
                return Ok(json!({"ok": false, "error": tr("the password database is disabled")}).to_string());
            }
            (g.cfg.database.clone(), g.cfg.keyfile.clone())
        };
        let keyfile = match read_keyfile(keyfile.as_ref()) {
            Ok(k) => k,
            Err(e) => return Ok(json!({"ok": false, "error": e}).to_string()),
        };
        let creds = Credentials { password, keyfile };
        // Lecture (avec délai) et dérivation Argon2 hors de la boucle D-Bus.
        let open_path = path.clone();
        let result = blocking::unblock(move || {
            let v = Vault::open(&open_path, creds)?;
            Ok::<_, String>((v, quick_stat(&open_path)))
        })
        .await;
        let unlocked = result.is_ok();
        let reply = {
            let mut g = self.shared.lock().unwrap();
            match result {
                Ok((v, stat)) => {
                    g.last_stat = stat;
                    g.vault = Some(v);
                    g.unlocked_at = Some(Instant::now());
                    g.message.clear();
                                json!({"ok": true}).to_string()
                }
                Err(e) => json!({"ok": false, "error": e}).to_string(),
            }
        };
        if unlocked {
            let _ = Self::changed(&emitter).await;
            spawn_fidelity_check(self.shared.clone(), Which::Main);
        }
        Ok(reply)
    }

    /// Déverrouille la base séparée des codes à usage unique. Le mot de passe est ignoré si
    /// la base s'ouvre par le seul fichier clé. Renvoie {ok} ou {ok:false, error}.
    async fn unlock_otp(
        &self,
        password: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let mut password = Zeroizing::new(password);
        let (path, keyfile, keyfile_only) = {
            let g = self.shared.lock().unwrap();
            if !g.otp_configured() {
                return Ok(json!({"ok": false, "error": tr("no separate database for one-time codes")}).to_string());
            }
            (g.cfg.otp_database.clone(), g.cfg.otp_keyfile.clone(), g.otp_keyfile_only())
        };
        let keyfile = match read_keyfile(keyfile.as_ref()) {
            Ok(k) => k,
            Err(e) => return Ok(json!({"ok": false, "error": e}).to_string()),
        };
        if keyfile_only {
            password = Zeroizing::new(String::new());
        }
        // Dérivation Argon2 hors de la boucle D-Bus.
        let result = blocking::unblock(move || {
            let v = Vault::open(&path, Credentials { password, keyfile })?;
            let stat = quick_stat(&path);
            Ok::<_, String>((v, stat))
        })
        .await;
        let reply = match result {
            Ok((v, stat)) => {
                let mut g = self.shared.lock().unwrap();
                g.otp_last_stat = stat;
                g.otp_vault = Some(v);
                g.otp_unlocked_at = Some(Instant::now());
                json!({"ok": true}).to_string()
            }
            Err(e) => return Ok(json!({"ok": false, "error": e}).to_string()),
        };
        let _ = Self::changed(&emitter).await;
        spawn_fidelity_check(self.shared.clone(), Which::Otp);
        Ok(reply)
    }

    async fn lock(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        self.shared.lock().unwrap().lock(&tr("locked"));
        let _ = Self::changed(&emitter).await;
        Ok(true)
    }

    /// Réglages affichés par la page Paramètres.
    async fn get_settings(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let g = self.shared.lock().unwrap();
        let policies: Vec<_> = RELOCK_POLICIES
            .iter()
            .map(|(id, label)| json!({"id": id, "label": label}))
            .collect();
        Ok(json!({
            "database": g.cfg.database.to_string_lossy(),
            "database_enabled": g.cfg.database_enabled,
            "otp_new_entry_group": g.cfg.otp_new_entry_group,
            "relock_policy": g.cfg.relock_policy,
            "new_entry_group": g.cfg.new_entry_group,
            "totp_enabled": g.cfg.totp_enabled,
            "keyfile": g.cfg.keyfile.as_ref().map(|p| p.to_string_lossy().to_string()),
            "otp_database": g.cfg.otp_database.to_string_lossy(),
            "otp_keyfile": g.cfg.otp_keyfile.as_ref().map(|p| p.to_string_lossy().to_string()),
            "otp_keyfile_only": g.otp_keyfile_only(),
            "otp_state": g.otp_state(),
            "home": crate::config::home().to_string_lossy(),
            "policies": policies,
            "state": g.state(),
            "entries": g.vault.as_ref().map(|v| v.entry_count()),
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string())
    }

    /// Dossiers d'une base déverrouillée (`target` = "main" ou "otp") et dossier actuel de ses
    /// nouvelles entrées.
    async fn list_groups(
        &self,
        target: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let g = self.shared.lock().unwrap();
        let (vault, current) = match target.as_str() {
            "otp" => (g.otp_vault.as_ref(), &g.cfg.otp_new_entry_group),
            _ => (g.vault.as_ref(), &g.cfg.new_entry_group),
        };
        let groups = vault.map(|v| crate::vault::group_paths(&v.db));
        Ok(json!({"current": current, "groups": groups}).to_string())
    }

    /// Dossier des nouvelles entrées d'une base ("" = racine ; créé au premier enregistrement
    /// s'il n'existe pas).
    async fn set_new_entry_group(
        &self,
        target: String,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        let clean = path.split('/').map(str::trim).filter(|p| !p.is_empty()).collect::<Vec<_>>().join("/");
        {
            let mut g = self.shared.lock().unwrap();
            match target.as_str() {
                "otp" => g.cfg.otp_new_entry_group = clean,
                _ => g.cfg.new_entry_group = clean,
            }
            let cfg_path = g.cfg_path.clone();
            g.cfg.save(&cfg_path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(true)
    }

    /// Active ou désactive la base des mots de passe ; désactivée, elle est verrouillée et le
    /// clavier ne la propose plus.
    async fn set_database_enabled(
        &self,
        enabled: bool,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        {
            let mut g = self.shared.lock().unwrap();
            if !enabled {
                g.lock(&tr("locked"));
            }
            g.cfg.database_enabled = enabled;
            let cfg_path = g.cfg_path.clone();
            g.cfg.save(&cfg_path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(true)
    }

    /// Désinstallation complète, lancée hors de ce service (qui sera arrêté en cours de route).
    async fn uninstall(
        &self,
        remove_settings: bool,
        remove_backups: bool,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        const SCRIPT: &str = "/usr/libexec/keepass-kbd/uninstall";
        if !std::path::Path::new(SCRIPT).exists() {
            return Ok(json!({"ok": false, "error": tr("uninstall script not found")}).to_string());
        }
        let mut cmd = std::process::Command::new("systemd-run");
        cmd.args(["--user", "--collect", "--unit=keepass-kbd-uninstall", SCRIPT]);
        if remove_settings {
            cmd.arg("--remove-settings");
        }
        if remove_backups {
            cmd.arg("--remove-backups");
        }
        match cmd.status() {
            Ok(st) if st.success() => {
                self.shared.lock().unwrap().lock(&tr("uninstalling"));
                Ok(json!({"ok": true}).to_string())
            }
            Ok(st) => Ok(json!({"ok": false, "error": format!("systemd-run : {st}")}).to_string()),
            Err(e) => Ok(json!({"ok": false, "error": format!("systemd-run : {e}")}).to_string()),
        }
    }

    async fn set_relock_policy(
        &self,
        policy: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        if !RELOCK_POLICIES.iter().any(|(id, _)| *id == policy) {
            return Err(failed(format!("unknown policy: {policy}")));
        }
        let mut g = self.shared.lock().unwrap();
        g.cfg.relock_policy = policy;
        let path = g.cfg_path.clone();
        g.cfg.save(&path).map_err(failed)?;
        Ok(true)
    }

    /// Active ou désactive les codes à usage unique (TOTP) dans le clavier.
    async fn set_totp_enabled(
        &self,
        enabled: bool,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        {
            let mut g = self.shared.lock().unwrap();
            g.cfg.totp_enabled = enabled;
            let path = g.cfg_path.clone();
            g.cfg.save(&path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(true)
    }

    /// Contenu d'un dossier pour le choix du fichier .kdbx dans les Paramètres.
    /// Le sélecteur de Sailfish tourne dans l'application Paramètres (groupe « privileged »),
    /// qui ne peut pas lire les montages FUSE sans allow_other (rclone, sshfs…) : le service,
    /// lui, tourne sous l'identité de l'utilisateur. Dossiers et fichiers .kdbx uniquement.
    async fn list_dir(
        &self,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let current = self.shared.lock().unwrap().cfg.database.clone();
        Ok(list_files_json(&path, "kdbx", &current))
    }

    /// Comme `ListDir`, pour un type de fichier : "kdbx" (bases), "key" (fichiers clés : tout
    /// fichier ordinaire), "dir" (dossiers seuls, pour choisir où créer un fichier).
    async fn list_files(
        &self,
        path: String,
        kind: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let current = self.shared.lock().unwrap().cfg.database.clone();
        Ok(list_files_json(&path, &kind, &current))
    }

    /// Fichier clé de la base des mots de passe (`target` = "main") ou de la base des codes
    /// ("otp") ; chemin vide = aucun. La base concernée est verrouillée.
    async fn set_keyfile(
        &self,
        target: String,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let path = path.trim_start_matches("file://").trim().to_string();
        let keyfile = if path.is_empty() { None } else { Some(PathBuf::from(&path)) };
        if let Some(p) = &keyfile {
            if let Err(e) = crate::keyfile::read(p) {
                return Ok(json!({"ok": false, "error": e}).to_string());
            }
        }
        {
            let mut g = self.shared.lock().unwrap();
            match target.as_str() {
                "main" => {
                    g.lock(&tr("locked"));
                    g.cfg.keyfile = keyfile;
                }
                "otp" => {
                    g.lock_otp();
                    if keyfile.is_none() {
                        g.cfg.otp_keyfile_only = false;
                    }
                    g.cfg.otp_keyfile = keyfile;
                }
                _ => return Err(failed(format!("unknown target: {target}"))),
            }
            let cfg_path = g.cfg_path.clone();
            g.cfg.save(&cfg_path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(json!({"ok": true}).to_string())
    }

    /// Base séparée des codes à usage unique ; chemin vide = codes dans la base des mots de passe.
    async fn set_otp_database(
        &self,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let path = PathBuf::from(path.trim_start_matches("file://").trim());
        {
            let mut g = self.shared.lock().unwrap();
            if !path.as_os_str().is_empty() {
                if !is_kdbx(&path) {
                    return Ok(json!({"ok": false, "error": tr("this file is not a readable KeePass (.kdbx) database")}).to_string());
                }
                if path == g.cfg.database {
                    return Ok(json!({"ok": false, "error": tr("choose a database different from the password database")}).to_string());
                }
            }
            g.lock_otp();
            g.cfg.otp_database = path;
            let cfg_path = g.cfg_path.clone();
            g.cfg.save(&cfg_path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(json!({"ok": true}).to_string())
    }

    /// Base des codes ouverte par le seul fichier clé (sans mot de passe).
    async fn set_otp_keyfile_only(
        &self,
        enabled: bool,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        {
            let mut g = self.shared.lock().unwrap();
            if enabled && g.cfg.otp_keyfile.is_none() {
                return Ok(json!({"ok": false, "error": tr("choose a key file first")}).to_string());
            }
            g.lock_otp();
            g.cfg.otp_keyfile_only = enabled;
            let cfg_path = g.cfg_path.clone();
            g.cfg.save(&cfg_path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(json!({"ok": true}).to_string())
    }

    /// Crée un fichier clé KeePass (XML 2.0) ; n'écrase jamais un fichier existant.
    async fn create_keyfile(
        &self,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let path = PathBuf::from(path.trim_start_matches("file://").trim());
        Ok(match crate::keyfile::create(&path) {
            Ok(()) => json!({"ok": true, "path": path.to_string_lossy()}).to_string(),
            Err(e) => json!({"ok": false, "error": e}).to_string(),
        })
    }

    /// Crée une base vide (KDBX 4, Argon2id) protégée par un mot de passe et/ou un fichier clé
    /// existant ; n'écrase jamais un fichier existant. Renvoie {ok, path} ou {ok:false, error}.
    async fn create_database(
        &self,
        path: String,
        password: String,
        keyfile: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let password = Zeroizing::new(password);
        let path = PathBuf::from(path.trim_start_matches("file://").trim());
        let keyfile = keyfile.trim_start_matches("file://").trim().to_string();
        let keyfile = match read_keyfile((!keyfile.is_empty()).then(|| PathBuf::from(keyfile)).as_ref()) {
            Ok(k) => k,
            Err(e) => return Ok(json!({"ok": false, "error": e}).to_string()),
        };
        let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "KeePass".into());
        let target = path.clone();
        let r = blocking::unblock(move || {
            crate::vault::create_database(&target, &Credentials { password, keyfile }, &name)
        })
        .await;
        Ok(match r {
            Ok(()) => json!({"ok": true, "path": path.to_string_lossy()}).to_string(),
            Err(e) => json!({"ok": false, "error": e}).to_string(),
        })
    }

    /// Change de base : vérifie le fichier, verrouille et enregistre la configuration.
    async fn set_database(
        &self,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let path = PathBuf::from(path.trim_start_matches("file://"));
        if !is_kdbx(&path) {
            return Ok(json!({"ok": false, "error": tr("this file is not a readable KeePass (.kdbx) database")}).to_string());
        }
        {
            let mut g = self.shared.lock().unwrap();
            g.lock(&tr("locked (new database)"));
            g.cfg.database = path;
            g.last_stat = None;
            let cfg_path = g.cfg_path.clone();
            g.cfg.save(&cfg_path).map_err(failed)?;
        }
        let _ = Self::changed(&emitter).await;
        Ok(json!({"ok": true}).to_string())
    }

    /// Liste JSON des entrées correspondant à la recherche (sans mot de passe).
    async fn search(
        &self,
        query: String,
        limit: i32,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let g = self.shared.lock().unwrap();
        let v = g.vault.as_ref().ok_or_else(|| failed(tr("database locked")))?;
        let tokens: Vec<String> = fold(&query).split_whitespace().map(String::from).collect();
        let mut items: Vec<_> = v
            .summaries()
            .into_iter()
            .filter(|s| {
                let hay = fold(&format!("{} {} {} {} {}", s.title, s.username, s.url, s.extra_urls.join(" "), s.group));
                tokens.iter().all(|t| hay.contains(t.as_str()))
            })
            .collect();
        items.sort_by(|a, b| {
            let ua = g.usage.get(&a.id).copied().unwrap_or(0);
            let ub = g.usage.get(&b.id).copied().unwrap_or(0);
            ub.cmp(&ua).then_with(|| fold(&a.title).cmp(&fold(&b.title)))
        });
        if limit > 0 {
            items.truncate(limit as usize);
        }
        g.enrich(&mut items);
        Ok(serde_json::to_string(&items).unwrap())
    }

    /// Entrées suggérées pour une origine (site web ou app://identifiant), meilleures d'abord.
    async fn suggest(
        &self,
        origin: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let g = self.shared.lock().unwrap();
        let v = g.vault.as_ref().ok_or_else(|| failed(tr("database locked")))?;
        let mut items = v.suggestions(&origin);
        items.sort_by(|(sa, a), (sb, b)| {
            let ua = g.usage.get(&a.id).copied().unwrap_or(0);
            let ub = g.usage.get(&b.id).copied().unwrap_or(0);
            sb.cmp(sa).then(ub.cmp(&ua)).then_with(|| fold(&a.title).cmp(&fold(&b.title)))
        });
        let mut list: Vec<_> = items.into_iter().take(10).map(|(_, e)| e).collect();
        g.enrich(&mut list);
        Ok(serde_json::to_string(&list).unwrap())
    }

    /// Titre proposé pour une nouvelle entrée (nom de l'application ou du site).
    async fn suggest_title(
        &self,
        origin: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        Ok(crate::titles::suggest_title(&origin))
    }

    /// Valeur d'un champ (username, password, url, title, notes) d'une entrée.
    async fn get_field(
        &self,
        id: String,
        field: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let mut g = self.shared.lock().unwrap();
        let value = g
            .vault
            .as_ref()
            .ok_or_else(|| failed(tr("database locked")))?
            .field(&id, &field)
            .map_err(failed)?;
        g.usage.insert(id, now_secs());
        save_usage(&g.usage);
        Ok(value)
    }

    /// Code TOTP actuel d'une entrée (JSON : code, remaining, period). La clé secrète reste ici.
    async fn totp(
        &self,
        id: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let g = self.shared.lock().unwrap();
        if !g.cfg.totp_enabled {
            return Err(failed(tr("one-time codes are disabled")));
        }
        let v = g.vault.as_ref().ok_or_else(|| failed(tr("database locked")))?;
        if g.otp_configured() {
            // Base séparée : code de l'entrée liée ; {otp_locked} si elle est verrouillée.
            let Some(o) = g.otp_vault.as_ref() else {
                return Ok(json!({"otp_locked": true, "keyfile_only": g.otp_keyfile_only()}).to_string());
            };
            if let Some(oid) = v.summary(&id).and_then(|src| o.counterpart(&src, true)) {
                let (code, remaining, period) = o.totp(&oid).map_err(|e| failed(tr(&e)))?;
                return Ok(json!({"code": code, "remaining": remaining, "period": period}).to_string());
            }
        }
        let (code, remaining, period) = v.totp(&id).map_err(|e| failed(tr(&e)))?;
        Ok(json!({"code": code, "remaining": remaining, "period": period}).to_string())
    }

    async fn generate(
        &self,
        length: u32,
        classes: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        generator::generate(length as usize, &classes).map_err(failed)
    }

    /// Ajoute une entrée et l'écrit dans le fichier. Renvoie {ok, id} ou {ok:false, error}.
    /// Ajoute une entrée. La préparation et l'écriture se font en arrière-plan (plusieurs
    /// dérivations de clé Argon2) ; le résultat est annoncé par une notification système.
    /// Renvoie aussitôt {ok:true, pending:true}, ou {ok:false, error} si l'ajout ne peut pas démarrer.
    async fn add_entry(
        &self,
        title: String,
        username: String,
        password: String,
        url: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let password = Zeroizing::new(password);
        let group = self.shared.lock().unwrap().cfg.new_entry_group.clone();
        let done = (tr("KeePass entry saved"), tr1("“%1” was added to the database", &title));
        Ok(self.save_in_background(conn, Which::Main, done, move |snap| {
            crate::vault::prepare_add(snap, &group, &title, &username, &password, &url)
        }))
    }

    /// Analyse un code de double authentification saisi ou collé (clé secrète ou URI otpauth)
    /// pour l'aperçu, sans rien enregistrer. `title` et `username` (ceux de l'entrée) servent
    /// d'étiquette à une clé seule. Renvoie {ok, issuer, account, digits, period, code,
    /// remaining} ou {ok:false, error}. Le code affiché permet de terminer l'activation sur le site.
    async fn otp_preview(
        &self,
        input: String,
        title: String,
        username: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let input = Zeroizing::new(input);
        Ok(match crate::totp::normalize_input(&input, &title, &username) {
            Ok(uri) => otp_description(&uri),
            Err(e) => json!({"ok": false, "error": tr(e)}).to_string(),
        })
    }

    /// Ajoute (ou remplace, si `replace`) le code à usage unique d'une entrée. Écriture en
    /// arrière-plan comme `AddEntry`. Renvoie {ok:true, pending:true}, {ok:false, exists:true}
    /// si l'entrée a déjà un code et que `replace` est faux, ou {ok:false, error}.
    async fn set_otp(
        &self,
        id: String,
        input: String,
        replace: bool,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let input = Zeroizing::new(input);
        // Base séparée : `target` = entrée correspondante déjà présente dans la base des codes.
        let (src, separate, target, has_totp, otp_group) = {
            let g = self.shared.lock().unwrap();
            let otp_group = g.cfg.otp_new_entry_group.clone();
            let v = g.vault.as_ref().ok_or_else(|| failed(tr("database locked")))?;
            let src = v.summary(&id).ok_or_else(|| failed(tr("entry not found")))?;
            if g.otp_configured() {
                let Some(o) = g.otp_vault.as_ref() else {
                    return Ok(json!({"ok": false, "otp_locked": true, "keyfile_only": g.otp_keyfile_only(),
                                     "error": tr("the one-time code database is locked")})
                    .to_string());
                };
                let target = o.counterpart(&src, false);
                let has = target.as_ref().is_some_and(|t| o.totp(t).is_ok());
                (src, true, target, has, otp_group)
            } else {
                let has = v.totp(&id).is_ok();
                (src, false, None, has, otp_group)
            }
        };
        if has_totp && !replace {
            return Ok(json!({"ok": false, "exists": true, "error": tr("this entry already has a one-time code")}).to_string());
        }
        let uri = match crate::totp::normalize_input(&input, &src.title, &src.username) {
            Ok(uri) => uri,
            Err(e) => return Ok(json!({"ok": false, "error": tr(e)}).to_string()),
        };
        let done = (tr("One-time code saved"), tr1("“%1” now has a one-time code", &src.title));
        Ok(if separate {
            self.save_in_background(conn, Which::Otp, done, move |snap| match &target {
                Some(t) => crate::vault::prepare_set_otp(snap, t, &uri, Some(&src.id)),
                None => crate::vault::prepare_add_otp_entry(snap, &otp_group, &src, &uri),
            })
        } else {
            self.save_in_background(conn, Which::Main, done, move |snap| crate::vault::prepare_set_otp(snap, &id, &uri, None))
        })
    }

    /// Lit le QR code de double authentification d'une image (capture d'écran ou photo).
    /// Renvoie {ok, uri, issuer, account, digits, period, code, remaining} ou {ok:false, error}.
    async fn otp_from_image(
        &self,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        // Décodage hors de la boucle D-Bus : une grande photo prend une fraction de seconde.
        // Les photos du scan à l'appareil photo (OtpScanPath) sont effacées dès leur lecture.
        let decoded = blocking::unblock(move || {
            let path = PathBuf::from(path);
            let r = crate::qr::decode_file(&path);
            if path == scan_path() {
                let _ = std::fs::remove_file(&path);
            }
            r
        })
        .await;
        let contents = match decoded {
            Ok(c) => c,
            Err(e) => return Ok(json!({"ok": false, "error": tr1("this image cannot be read (%1)", &e)}).to_string()),
        };
        let Some(content) = crate::qr::pick_otp(&contents) else {
            return Ok(json!({"ok": false, "error": tr("no QR code found in this image")}).to_string());
        };
        if !content.trim().to_ascii_lowercase().starts_with("otpauth") {
            return Ok(json!({"ok": false, "error": tr("this QR code does not contain a one-time code")}).to_string());
        }
        Ok(match crate::totp::normalize_input(content, "", "") {
            Ok(uri) => {
                let mut v: serde_json::Value = serde_json::from_str(&otp_description(&uri)).unwrap_or_default();
                v["uri"] = json!(uri.as_str());
                v.to_string()
            }
            Err(e) => json!({"ok": false, "error": tr(e)}).to_string(),
        })
    }

    /// Fichier où la page des Paramètres enregistre les photos du scan à l'appareil photo :
    /// dossier d'exécution de la session (en mémoire, propre à l'utilisateur).
    async fn otp_scan_path(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        Ok(scan_path().to_string_lossy().to_string())
    }

    /// Images récentes où chercher un QR code : captures d'écran puis photos, les plus récentes
    /// d'abord. Renvoie [{path, name, mtime}].
    async fn recent_images(
        &self,
        limit: i32,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let home = crate::config::home();
        let mut items: Vec<(u64, PathBuf)> = Vec::new();
        for dir in ["Pictures/Screenshots", "Pictures/Camera", "Pictures", "Downloads"] {
            let Ok(rd) = std::fs::read_dir(home.join(dir)) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
                if !matches!(ext.as_str(), "png" | "jpg" | "jpeg") || !p.is_file() {
                    continue;
                }
                let mtime = e
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map_or(0, |d| d.as_secs());
                items.push((mtime, p));
            }
        }
        items.sort_by(|a, b| b.0.cmp(&a.0));
        items.truncate(if limit > 0 { limit as usize } else { 12 });
        let out: Vec<_> = items
            .into_iter()
            .map(|(mtime, p)| {
                json!({
                    "path": p.to_string_lossy(),
                    "name": p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
                    "mtime": mtime,
                })
            })
            .collect();
        Ok(serde_json::to_string(&out).unwrap())
    }

    /// Entrées pour la page « Codes à usage unique » des Paramètres : titre, identifiant et
    /// présence d'un code seulement (jamais de mot de passe ni de clé). Base déverrouillée requise.
    async fn otp_entries(
        &self,
        query: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let g = self.shared.lock().unwrap();
        let v = g.vault.as_ref().ok_or_else(|| failed(tr("database locked")))?;
        let tokens: Vec<String> = fold(&query).split_whitespace().map(String::from).collect();
        let mut items: Vec<_> = v
            .summaries()
            .into_iter()
            .filter(|s| {
                let hay = fold(&format!("{} {} {} {} {}", s.title, s.username, s.url, s.extra_urls.join(" "), s.group));
                tokens.iter().all(|t| hay.contains(t.as_str()))
            })
            .collect();
        items.sort_by_key(|s| fold(&s.title));
        items.truncate(100);
        g.enrich(&mut items);
        let out: Vec<_> = items
            .iter()
            .take(100)
            .map(|s| json!({"id": s.id, "title": s.title, "username": s.username, "has_totp": s.has_totp}))
            .collect();
        Ok(serde_json::to_string(&out).unwrap())
    }

    #[zbus(signal)]
    async fn changed(emitter: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;
}

impl Service {
    /// Écriture en arrière-plan : instantané de la base, préparation hors verrou (dérivations
    /// Argon2), puis écriture ; le résultat est annoncé par une notification (`done` : titre et
    /// texte en cas de succès). Renvoie aussitôt la réponse JSON pour l'appelant.
    fn save_in_background(
        &self,
        conn: &zbus::Connection,
        which: Which,
        done: (String, String),
        prepare: impl FnOnce(&crate::vault::Snapshot) -> Result<crate::vault::Prepared, String> + Send + 'static,
    ) -> String {
        let snapshot = {
            let mut g = self.shared.lock().unwrap();
            if g.saving {
                return json!({"ok": false, "error": tr("a save is already in progress")}).to_string();
            }
            let Some(v) = g.vault_of(which) else {
                return json!({"ok": false, "error": tr("database locked")}).to_string();
            };
            match v.snapshot() {
                Ok(snap) => {
                    g.saving = true;
                    snap
                }
                Err(e) => {
                    log_error(&format!("save refused: {e}"));
                    return json!({"ok": false, "error": e}).to_string();
                }
            }
        };
        let shared = self.shared.clone();
        let conn = zbus::blocking::Connection::from(conn.clone());
        std::thread::spawn(move || {
            let (keep, path) = {
                let g = shared.lock().unwrap();
                (g.cfg.backups_keep, which.path(&g.cfg))
            };
            let prepared = prepare(&snapshot);
            let result = {
                let mut g = shared.lock().unwrap();
                g.saving = false;
                let r = match (prepared, g.vault_of(which)) {
                    (Ok(p), Some(v)) => v.commit(&snapshot, p, &which.backup_dir(), keep),
                    (Ok(_), None) => Err(tr("the database was locked during the save")),
                    (Err(e), _) => Err(e),
                };
                match which {
                    Which::Main => {
                        g.last_stat = quick_stat(&path);
                        if let Ok(id) = &r {
                            g.usage.insert(id.clone(), now_secs());
                            save_usage(&g.usage);
                        }
                    }
                    Which::Otp => g.otp_last_stat = quick_stat(&path),
                }
                r
            };
            match result {
                Ok(_) => {
                    emit_changed(&conn);
                    notify_blocking(&conn, &done.0, &done.1);
                }
                Err(e) => {
                    log_error(&format!("save refused: {e}"));
                    notify_blocking(&conn, &tr("KeePass save failed"), &e);
                }
            }
        });
        json!({"ok": true, "pending": true}).to_string()
    }
}

/// Photo temporaire du scan de QR code à l'appareil photo.
fn scan_path() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir())
        .join("keepass-kbd-scan.jpg")
}

/// Aperçu JSON d'une URI otpauth valide : émetteur, compte, paramètres et code actuel.
fn otp_description(uri: &str) -> String {
    match crate::totp::describe(uri) {
        Some(d) => {
            let (code, remaining) = d.spec.code_now();
            json!({
                "ok": true,
                "issuer": d.issuer,
                "account": d.account,
                "digits": d.spec.digits,
                "period": d.spec.period,
                "code": code,
                "remaining": remaining,
            })
            .to_string()
        }
        None => json!({"ok": false, "error": tr(crate::totp::ERR_INVALID)}).to_string(),
    }
}

fn emit_changed(conn: &zbus::blocking::Connection) {
    let _ = conn.emit_signal(None::<&str>, OBJECT_PATH, INTERFACE, "Changed", &());
}

/// Surveillance : rechargement quand le fichier change, verrouillage après inactivité.
/// Les accès au fichier (stat, lecture) se font sans tenir le verrou partagé : un fichier qui ne
/// répond plus (montage réseau) ne bloque ni le service D-Bus ni le clavier.
pub fn spawn_watcher(shared: Shared, conn: zbus::blocking::Connection) {
    std::thread::spawn(move || loop {
        let poll = shared.lock().unwrap().cfg.poll_seconds.max(2);
        std::thread::sleep(Duration::from_secs(poll));
        let mut changed = false;
        let mut reloaded = Vec::new();
        for which in [Which::Main, Which::Otp] {
            let (c, r) = watch_one(&shared, which);
            changed |= c;
            if r {
                reloaded.push(which);
            }
        }
        if changed {
            emit_changed(&conn);
        }
        for which in reloaded {
            spawn_fidelity_check(shared.clone(), which);
        }
    });
}

/// Une base : reverrouillage à l'échéance, rechargement si le fichier a changé.
/// Renvoie (changement à annoncer, base rechargée).
fn watch_one(shared: &Shared, which: Which) -> (bool, bool) {
    let (path, last) = {
        let mut g = shared.lock().unwrap();
        if g.vault_of(which).is_none() {
            return (false, false);
        }
        let unlocked_at = match which {
            Which::Main => g.unlocked_at,
            Which::Otp => g.otp_unlocked_at,
        };
        let expired = match (g.cfg.relock_after(), unlocked_at) {
            (Some(max), Some(t)) => t.elapsed() > max,
            _ => false,
        };
        if expired {
            match which {
                Which::Main => g.lock(&tr("master password required again")),
                Which::Otp => g.lock_otp(),
            }
            return (true, false);
        }
        let last = match which {
            Which::Main => g.last_stat,
            Which::Otp => g.otp_last_stat,
        };
        (which.path(&g.cfg), last)
    };
    // Hors verrou : stat puis lecture, chacun avec son délai.
    let stat = quick_stat(&path);
    if stat.is_none() || stat == last {
        return (false, false);
    }
    let (raw, fp) = match crate::vault::read_file(&path) {
        Ok(r) => r,
        Err(e) => {
            // Fichier momentanément illisible (réseau coupé…) : la base déjà en mémoire reste
            // utilisable ; last_stat n'est pas mis à jour, la lecture sera retentée.
            eprintln!("lecture impossible ({which:?}), nouvel essai plus tard : {e}");
            return (false, false);
        }
    };
    let mut g = shared.lock().unwrap();
    if which.path(&g.cfg) != path || g.vault_of(which).is_none() {
        return (false, false); // base changée ou verrouillée entre-temps
    }
    match which {
        Which::Main => g.last_stat = stat,
        Which::Otp => g.otp_last_stat = stat,
    }
    match g.vault_of(which).unwrap().reload_from(raw, fp) {
        Ok(true) => {
            if which == Which::Main {
                g.message = tr("database reloaded");
            }
            eprintln!("base rechargée après modification du fichier ({which:?})");
            (true, true)
        }
        Ok(false) => (false, false),
        Err(e) => {
            eprintln!("rechargement impossible ({which:?}) : {e}");
            match which {
                Which::Main => g.lock(&tr1("locked: %1", &e)),
                Which::Otp => g.lock_otp(),
            }
            (true, false)
        }
    }
}

/// Verrouille la base dès la mise en veille (écran éteint) ou le verrouillage de l'écran (signaux MCE).
pub fn spawn_screen_lock_listener(shared: Shared, conn: zbus::blocking::Connection) {
    std::thread::spawn(move || {
        let run = || -> zbus::Result<()> {
            let system = zbus::blocking::Connection::system()?;
            let rule = zbus::MatchRule::builder()
                .msg_type(zbus::message::Type::Signal)
                .interface("com.nokia.mce.signal")?
                .build();
            let iter = zbus::blocking::MessageIterator::for_match_rule(rule, &system, None)?;
            for msg in iter {
                let Ok(msg) = msg else { continue };
                let member = msg.header().member().map(|m| m.to_string()).unwrap_or_default();
                let value: String = msg.body().deserialize().unwrap_or_default();
                let reason = match (member.as_str(), value.as_str()) {
                    ("display_status_ind", "off") => "locked (sleep)",
                    ("tklock_mode_ind", "locked") => "locked with the screen",
                    _ => continue,
                };
                let mut g = shared.lock().unwrap();
                if g.cfg.lock_on_sleep() && (g.vault.is_some() || g.otp_vault.is_some()) {
                    g.lock(&tr(reason));
                    drop(g);
                    eprintln!("{reason}");
                    emit_changed(&conn);
                }
            }
            Ok(())
        };
        if let Err(e) = run() {
            eprintln!("écoute de la mise en veille indisponible : {e}");
        }
    });
}
