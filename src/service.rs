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
use crate::vault::{quick_stat, Credentials, Vault};

pub const OBJECT_PATH: &str = "/org/keepasskbd/Daemon";
pub const INTERFACE: &str = "org.keepasskbd.Daemon1";

pub struct Inner {
    pub cfg: Config,
    pub cfg_path: PathBuf,
    pub vault: Option<Vault>,
    pub unlocked_at: Option<Instant>,
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
        } else if !self.cfg.database.exists() {
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
        let sender = hdr.sender().ok_or_else(|| fdo::Error::AccessDenied("expéditeur inconnu".into()))?;
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
            return Err(fdo::Error::AccessDenied(format!("appelant non autorisé : {}", exe.display())));
        }
        // L'application Paramètres tourne avec le groupe effectif « privileged » (binaire setgid) :
        // son exécutable n'est alors pas lisible. Un processus ordinaire ne peut pas obtenir ce
        // groupe ; on l'accepte pour les réglages s'il a été lancé depuis un exécutable autorisé.
        if settings_ok && privileged_settings_process(pid, &settings) {
            return Ok(());
        }
        eprintln!("appel refusé depuis le processus {pid}");
        Err(fdo::Error::AccessDenied("processus appelant non autorisé".into()))
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
                std::fs::read(&p).map_err(|e| failed(format!("fichier clé {} : {e}", p.display())))?,
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
        self.shared.lock().unwrap().lock("verrouillée");
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
            "policies": policies,
            "state": g.state(),
            "entries": g.vault.as_ref().map(|v| v.entry_count()),
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string())
    }

    async fn set_relock_policy(
        &self,
        policy: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
    ) -> fdo::Result<bool> {
        self.check_caller(&hdr, conn, true).await?;
        if !RELOCK_POLICIES.iter().any(|(id, _)| *id == policy) {
            return Err(failed(format!("politique inconnue : {policy}")));
        }
        let mut g = self.shared.lock().unwrap();
        g.cfg.relock_policy = policy;
        let path = g.cfg_path.clone();
        g.cfg.save(&path).map_err(failed)?;
        Ok(true)
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
            return Ok(json!({"ok": false, "error": "ce fichier n'est pas une base KeePass (.kdbx) lisible"}).to_string());
        }
        {
            let mut g = self.shared.lock().unwrap();
            g.lock("verrouillée (nouvelle base)");
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
        let v = g.vault.as_ref().ok_or_else(|| failed("base verrouillée"))?;
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
        let v = g.vault.as_ref().ok_or_else(|| failed("base verrouillée"))?;
        let mut items = v.suggestions(&origin);
        items.sort_by(|(sa, a), (sb, b)| {
            let ua = g.usage.get(&a.id).copied().unwrap_or(0);
            let ub = g.usage.get(&b.id).copied().unwrap_or(0);
            sb.cmp(sa).then(ub.cmp(&ua)).then_with(|| fold(&a.title).cmp(&fold(&b.title)))
        });
        let list: Vec<_> = items.into_iter().take(10).map(|(_, e)| e).collect();
        Ok(serde_json::to_string(&list).unwrap())
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
            .ok_or_else(|| failed("base verrouillée"))?
            .field(&id, &field)
            .map_err(failed)?;
        g.usage.insert(id, now_secs());
        save_usage(&g.usage);
        Ok(value)
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
    async fn add_entry(
        &self,
        title: String,
        username: String,
        password: String,
        url: String,
        #[zbus(header)] hdr: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> fdo::Result<String> {
        self.check_caller(&hdr, conn, false).await?;
        let password = Zeroizing::new(password);
        let reply = {
            let mut g = self.shared.lock().unwrap();
                let group = g.cfg.new_entry_group.clone();
            let keep = g.cfg.backups_keep;
            let path = g.cfg.database.clone();
            let v = g.vault.as_mut().ok_or_else(|| failed("base verrouillée"))?;
            let r = v.add_entry(&group, &title, &username, &password, &url, "", &data_dir().join("backups"), keep);
            g.last_stat = quick_stat(&path);
            match r {
                Ok(id) => {
                    g.usage.insert(id.clone(), now_secs());
                    save_usage(&g.usage);
                    json!({"ok": true, "id": id}).to_string()
                }
                Err(e) => json!({"ok": false, "error": e}).to_string(),
            }
        };
        if reply.contains("\"ok\":true") {
            let _ = Self::changed(&emitter).await;
        }
        Ok(reply)
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
                g.lock("mot de passe maître à ressaisir");
                changed = true;
            } else {
                let path = g.cfg.database.clone();
                let stat = quick_stat(&path);
                if stat.is_some() && stat != g.last_stat {
                    g.last_stat = stat;
                    let r = g.vault.as_mut().unwrap().reload_if_changed();
                    match r {
                        Ok(true) => {
                            g.message = "base rechargée".into();
                            eprintln!("base rechargée après modification du fichier");
                            changed = true;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("rechargement impossible : {e}");
                            g.lock(&format!("verrouillée : {e}"));
                            changed = true;
                        }
                    }
                }
            }
        }
        if changed {
            emit_changed(&conn);
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
                    ("display_status_ind", "off") => "verrouillée (mise en veille)",
                    ("tklock_mode_ind", "locked") => "verrouillée avec l'écran",
                    _ => continue,
                };
                let mut g = shared.lock().unwrap();
                if g.cfg.lock_on_sleep() && g.vault.is_some() {
                    g.lock(reason);
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
