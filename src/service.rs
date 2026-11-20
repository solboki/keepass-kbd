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
        if self.vault.is_some() {
            "unlocked"
        } else if self.cfg.database.as_os_str().is_empty() || !self.cfg.database.is_file() {
            "missing"
        } else {
            "locked"
        }
    }

    pub fn status_json(&self) -> String {
        json!({
            "state": self.state(),
            "database": self.cfg.database.file_name().map(|s| s.to_string_lossy().to_string()),
            "entries": self.vault.as_ref().map(|v| v.entry_count()),
            "message": self.message,
            "totp_enabled": self.cfg.totp_enabled,
        })
        .to_string()
    }

    pub fn lock(&mut self, reason: &str) {
        self.unlocked_at = None;
        if self.vault.take().is_some() {
            self.message = reason.to_string();
        }
    }
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
pub fn spawn_fidelity_check(shared: Shared) {
    let snap = {
        let mut g = shared.lock().unwrap();
        match g.vault.as_mut().map(|v| v.snapshot()) {
            Some(Ok(s)) if !s.fidelity_ok => s,
            _ => return,
        }
    };
    std::thread::spawn(move || match crate::vault::check_fidelity(&snap.raw, &snap.db, &snap.key) {
        Ok(()) => {
            if let Some(v) = shared.lock().unwrap().vault.as_mut() {
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
            (g.cfg.database.clone(), g.cfg.keyfile.clone())
        };
        let keyfile = match keyfile {
            Some(p) => Some(Zeroizing::new(
                std::fs::read(&p).map_err(|e| failed(format!("key file {}: {e}", p.display())))?,
            )),
            None => None,
        };
        let creds = Credentials { password, keyfile };
        let result = Vault::open(&path, creds);
        let unlocked = result.is_ok();
        let reply = {
            let mut g = self.shared.lock().unwrap();
            match result {
                Ok(v) => {
                    g.last_stat = quick_stat(&path);
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
            spawn_fidelity_check(self.shared.clone());
        }
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
            "relock_policy": g.cfg.relock_policy,
            "new_entry_group": g.cfg.new_entry_group,
            "totp_enabled": g.cfg.totp_enabled,
            "policies": policies,
            "state": g.state(),
            "entries": g.vault.as_ref().map(|v| v.entry_count()),
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string())
    }

    /// Dossiers de la base (base déverrouillée) et dossier actuel des nouvelles entrées.
    async fn list_groups(
        &self,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, true).await?;
        let g = self.shared.lock().unwrap();
        let groups = g.vault.as_ref().map(|v| crate::vault::group_paths(&v.db));
        Ok(json!({"current": g.cfg.new_entry_group, "groups": groups}).to_string())
    }

    /// Dossier des nouvelles entrées ("" = racine ; créé au premier enregistrement s'il n'existe pas).
    async fn set_new_entry_group(
        &self,
        path: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        let clean: Vec<&str> = path.split('/').map(str::trim).filter(|p| !p.is_empty()).collect();
        let mut g = self.shared.lock().unwrap();
        g.cfg.new_entry_group = clean.join("/");
        let cfg_path = g.cfg_path.clone();
        g.cfg.save(&cfg_path).map_err(failed)?;
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
        let home = crate::config::home();
        let current = self.shared.lock().unwrap().cfg.database.clone();
        let mut dir = if path.is_empty() {
            current.parent().filter(|p| p.is_dir()).map(|p| p.to_path_buf()).unwrap_or_else(|| home.clone())
        } else {
            PathBuf::from(path)
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
                } else if name.to_lowercase().ends_with(".kdbx") {
                    files.push(name);
                }
            }
        }
        dirs.sort_by_key(|n| n.to_lowercase());
        files.sort_by_key(|n| n.to_lowercase());
        let parent = dir.parent().map(|p| p.to_string_lossy().to_string());
        Ok(json!({
            "path": dir.to_string_lossy(),
            "parent": parent,
            "home": home.to_string_lossy(),
            "dirs": dirs,
            "files": files,
            "error": error,
        })
        .to_string())
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
        let mut head = [0u8; 8];
        let ok = std::fs::File::open(&path)
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head))
            .is_ok()
            && head == [0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5];
        if !ok {
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
                let hay = fold(&format!("{} {} {} {}", s.title, s.username, s.url, s.group));
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
        let list: Vec<_> = items.into_iter().take(10).map(|(_, e)| e).collect();
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
        let (code, remaining, period) = g
            .vault
            .as_ref()
            .ok_or_else(|| failed(tr("database locked")))?
            .totp(&id)
            .map_err(|e| failed(tr(&e)))?;
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
        let snapshot = {
            let mut g = self.shared.lock().unwrap();
            if g.saving {
                return Ok(json!({"ok": false, "error": tr("a save is already in progress")}).to_string());
            }
            let v = g.vault.as_mut().ok_or_else(|| failed(tr("database locked")))?;
            match v.snapshot() {
                Ok(snap) => {
                    g.saving = true;
                    snap
                }
                Err(e) => {
                    log_error(&format!("save refused: {e}"));
                    return Ok(json!({"ok": false, "error": e}).to_string());
                }
            }
        };
        let shared = self.shared.clone();
        let conn = zbus::blocking::Connection::from(conn.clone());
        std::thread::spawn(move || {
            let (group, keep, path) = {
                let g = shared.lock().unwrap();
                (g.cfg.new_entry_group.clone(), g.cfg.backups_keep, g.cfg.database.clone())
            };
            let prepared = crate::vault::prepare_add(&snapshot, &group, &title, &username, &password, &url);
            let result = {
                let mut g = shared.lock().unwrap();
                g.saving = false;
                let r = match (prepared, g.vault.as_mut()) {
                    (Ok(p), Some(v)) => v.commit(&snapshot, p, &data_dir().join("backups"), keep),
                    (Ok(_), None) => Err(tr("the database was locked during the save")),
                    (Err(e), _) => Err(e),
                };
                g.last_stat = quick_stat(&path);
                if let Ok(id) = &r {
                    g.usage.insert(id.clone(), now_secs());
                    save_usage(&g.usage);
                }
                r
            };
            match result {
                Ok(_) => {
                    emit_changed(&conn);
                    notify_blocking(&conn, &tr("KeePass entry saved"), &tr1("“%1” was added to the database", &title));
                }
                Err(e) => {
                    log_error(&format!("save refused: {e}"));
                    notify_blocking(&conn, &tr("KeePass save failed"), &e);
                }
            }
        });
        Ok(json!({"ok": true, "pending": true}).to_string())
    }

    #[zbus(signal)]
    async fn changed(emitter: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;
}

fn emit_changed(conn: &zbus::blocking::Connection) {
    let _ = conn.emit_signal(None::<&str>, OBJECT_PATH, INTERFACE, "Changed", &());
}

/// Surveillance : rechargement quand le fichier change, verrouillage après inactivité.
pub fn spawn_watcher(shared: Shared, conn: zbus::blocking::Connection) {
    std::thread::spawn(move || loop {
        let poll = shared.lock().unwrap().cfg.poll_seconds.max(2);
        std::thread::sleep(Duration::from_secs(poll));
        let mut changed = false;
        let mut reloaded = false;
        {
            let mut g = shared.lock().unwrap();
            if g.vault.is_none() {
                continue;
            }
            let expired = match (g.cfg.relock_after(), g.unlocked_at) {
                (Some(max), Some(t)) => t.elapsed() > max,
                _ => false,
            };
            if expired {
                g.lock(&tr("master password required again"));
                changed = true;
            } else {
                let path = g.cfg.database.clone();
                let stat = quick_stat(&path);
                if stat.is_some() && stat != g.last_stat {
                    g.last_stat = stat;
                    let r = g.vault.as_mut().unwrap().reload_if_changed();
                    match r {
                        Ok(true) => {
                            reloaded = true;
                            g.message = tr("database reloaded");
                            eprintln!("base rechargée après modification du fichier");
                            changed = true;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("rechargement impossible : {e}");
                            g.lock(&tr1("locked: %1", &e));
                            changed = true;
                        }
                    }
                }
            }
        }
        if changed {
            emit_changed(&conn);
        }
        if reloaded {
            spawn_fidelity_check(shared.clone());
        }
    });
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
                if g.cfg.lock_on_sleep() && g.vault.is_some() {
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
