mod config;
mod generator;
mod service;
mod titles;
mod vault;

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use config::{default_config_path, Config};
use zeroize::Zeroizing;

const USAGE: &str = "\
keepass-kbd — service KeePass pour la disposition clavier Sailfish

  keepass-kbd daemon [--config FICHIER] [--bus-name NOM] [--allow-any-caller]
  keepass-kbd check  [--config FICHIER]   vérifie l'ouverture et la réécriture sans rien modifier
  keepass-kbd generate [LONGUEUR] [CLASSES]   ex. : generate 20 luds
  keepass-kbd make-test-db FICHIER MOTDEPASSE  (base de test, KDF légère)
";

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn read_password(prompt: &str) -> Zeroizing<String> {
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let fd = 0;
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    let is_tty = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if is_tty {
        term.c_lflag &= !libc::ECHO;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut line = Zeroizing::new(String::new());
    let _ = std::io::stdin().lock().read_line(&mut line);
    if is_tty {
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        eprintln!();
    }
    Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg_path = arg_value(&args, "--config").map(PathBuf::from).unwrap_or_else(default_config_path);
    let code = match args.first().map(String::as_str) {
        Some("daemon") => daemon(&args, &cfg_path),
        Some("check") => check(&cfg_path),
        Some("generate") => {
            let len = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
            let classes = args.get(2).cloned().unwrap_or_else(|| "luds".into());
            match generator::generate(len, &classes) {
                Ok(p) => {
                    println!("{p}");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Some("make-test-db") => make_test_db(&args),
        _ => {
            eprint!("{USAGE}");
            Err(String::new())
        }
    };
    if let Err(e) = code {
        if !e.is_empty() {
            eprintln!("erreur : {e}");
        }
        std::process::exit(1);
    }
}

fn daemon(args: &[String], cfg_path: &std::path::Path) -> Result<(), String> {
    let cfg = Config::load(cfg_path)?;
    let bus_name = arg_value(args, "--bus-name").unwrap_or_else(|| "org.keepasskbd.Daemon".into());
    let allow_any_caller = args.iter().any(|a| a == "--allow-any-caller");
    eprintln!("base : {}", cfg.database.display());
    let shared = Arc::new(Mutex::new(service::Inner {
        cfg,
        cfg_path: cfg_path.to_path_buf(),
        vault: None,
        unlocked_at: None,
        saving: false,
        last_stat: None,
        message: String::new(),
        usage: service::load_usage(),
    }));
    let svc = service::Service { shared: shared.clone(), allow_any_caller };
    let conn = zbus::blocking::connection::Builder::session()
        .and_then(|b| b.serve_at(service::OBJECT_PATH, svc))
        .and_then(|b| b.build())
        .map_err(|e| format!("D-Bus : {e}"))?;
    // Nom exclusif : ni remplacement par un autre processus, ni file d'attente.
    let reply = conn
        .request_name_with_flags(bus_name.as_str(), zbus::fdo::RequestNameFlags::DoNotQueue.into())
        .map_err(|e| format!("nom D-Bus {bus_name} : {e}"))?;
    if reply != zbus::fdo::RequestNameReply::PrimaryOwner {
        return Err(format!("le nom D-Bus {bus_name} est déjà pris ({reply:?})"));
    }
    service::spawn_watcher(shared.clone(), conn.clone());
    service::spawn_screen_lock_listener(shared, conn.clone());
    eprintln!("service prêt sur {bus_name}");
    loop {
        std::thread::park();
    }
}

fn check(cfg_path: &std::path::Path) -> Result<(), String> {
    let cfg = Config::load(cfg_path)?;
    println!("Base : {}", cfg.database.display());
    let version = keepass::Database::get_version(
        &mut std::fs::File::open(&cfg.database).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!("Format : {version}");
    let password = read_password("Mot de passe maître : ");
    let keyfile = match &cfg.keyfile {
        Some(p) => Some(Zeroizing::new(std::fs::read(p).map_err(|e| e.to_string())?)),
        None => None,
    };
    let t = Instant::now();
    let mut v = vault::Vault::open(&cfg.database, vault::Credentials { password, keyfile })?;
    println!("Ouverte en {:.1} s : {} entrées (hors corbeille)", t.elapsed().as_secs_f32(), v.entry_count());
    let t = Instant::now();
    match v.check_fidelity() {
        Ok(()) => println!(
            "Test de réécriture : OK ({:.1} s). L'ajout d'entrées est possible sans perte.",
            t.elapsed().as_secs_f32()
        ),
        Err(e) => println!("Test de réécriture : ÉCHEC — {e}"),
    }
    println!("Aucune modification n'a été faite.");
    Ok(())
}

fn make_test_db(args: &[String]) -> Result<(), String> {
    let (Some(path), Some(pw)) = (args.get(1), args.get(2)) else {
        return Err("usage : make-test-db FICHIER MOTDEPASSE".into());
    };
    let mut cfg = keepass::config::DatabaseConfig::default();
    cfg.kdf_config = keepass::config::KdfConfig::Argon2 {
        iterations: 2,
        memory: 8 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    };
    let mut db = keepass::Database::with_config(cfg);
    db.meta.database_name = Some("Base de test".into());
    {
        let mut root = db.root_mut();
        let mut g = root.add_group();
        g.name = "Applis".into();
        let mut e = g.add_entry();
        e.set_unprotected("Title", "Messagerie Jolla");
        e.set_unprotected("UserName", "moi@example.org");
        e.set_protected("Password", "secret-mail");
        e.set_unprotected("URL", "app://jolla-email");
    }
    {
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        e.set_unprotected("Title", "Banque");
        e.set_unprotected("UserName", "12345678");
        e.set_protected("Password", "é@#mot de passe");
        e.set_unprotected("URL", "https://banque.example");
        e.tags = vec!["finance".into()];
    }
    let mut out = Vec::new();
    db.save(&mut out, keepass::DatabaseKey::new().with_password(pw)).map_err(|e| e.to_string())?;
    std::fs::write(path, out).map_err(|e| e.to_string())?;
    println!("Base de test créée : {path}");
    Ok(())
}
