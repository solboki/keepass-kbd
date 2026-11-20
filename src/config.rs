use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Quand redemander le mot de passe maître.
pub const RELOCK_POLICIES: &[(&str, &str)] = &[
    ("restart", "à chaque redémarrage"),
    ("24h", "toutes les 24 heures"),
    ("1h", "toutes les heures"),
    ("30min", "toutes les 30 minutes"),
    ("5min", "toutes les 5 minutes"),
    ("wake", "à chaque sortie de veille"),
];

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Chemin de la base .kdbx.
    pub database: PathBuf,
    /// Fichier clé facultatif.
    pub keyfile: Option<PathBuf>,
    /// Quand redemander le mot de passe maître : restart, 24h, 1h, 30min, 5min, wake.
    pub relock_policy: String,
    /// Intervalle de surveillance du fichier, en secondes.
    pub poll_seconds: u64,
    /// Groupe où créer les nouvelles entrées ("" = racine, "Internet/Applis" = sous-groupe).
    pub new_entry_group: String,
    /// Nombre de sauvegardes locales à conserver.
    pub backups_keep: usize,
    /// Exécutables autorisés à lire la base (le clavier).
    pub allowed_callers: Vec<PathBuf>,
    /// Exécutables autorisés à modifier les réglages et verrouiller (l'application Paramètres).
    pub settings_callers: Vec<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            database: PathBuf::new(),
            keyfile: None,
            relock_policy: "30min".into(),
            poll_seconds: 15,
            new_entry_group: String::new(),
            backups_keep: 20,
            allowed_callers: vec![PathBuf::from("/usr/bin/maliit-server")],
            settings_callers: vec![PathBuf::from("/usr/bin/jolla-settings")],
        }
    }
}

impl Config {
    /// Durée maximale de déverrouillage, si la politique en fixe une.
    pub fn relock_after(&self) -> Option<std::time::Duration> {
        let minutes = match self.relock_policy.as_str() {
            "24h" => 24 * 60,
            "1h" => 60,
            "30min" => 30,
            "5min" => 5,
            _ => return None,
        };
        Some(std::time::Duration::from_secs(minutes * 60))
    }

    pub fn lock_on_sleep(&self) -> bool {
        self.relock_policy == "wake"
    }

    pub fn load(path: &Path) -> Result<Config, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => serde_json::from_str(&s).map_err(|e| format!("{} : {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let cfg = Config::default();
                let _ = cfg.save(path);
                Ok(cfg)
            }
            Err(e) => Err(format!("{} : {e}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self).unwrap()).map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/home/defaultuser"))
}

pub fn default_config_path() -> PathBuf {
    home().join(".config/keepass-kbd/config.json")
}

pub fn data_dir() -> PathBuf {
    home().join(".local/share/keepass-kbd")
}
