//! Proposition de titre pour une nouvelle entrée, d'après le site ou l'application en cours.

use std::path::PathBuf;

use crate::config::home;

/// `https://compte.laposte.fr/…` → « Laposte » ; `app://com.netflix.mediaclient` → « Netflix »
/// (nom affiché de l'application, lu dans son fichier .desktop).
pub fn suggest_title(origin: &str) -> String {
    let origin = origin.trim();
    if let Some(app) = origin.strip_prefix("app://") {
        let app = app.trim_end_matches('/');
        return app_display_name(app).unwrap_or_else(|| fallback_app_title(app));
    }
    let Some(host) = crate::vault::host_of(origin) else { return String::new() };
    let domain = crate::vault::registrable(&host);
    let core = domain.split('.').next().unwrap_or("");
    if core.len() <= 3 {
        core.to_uppercase()
    } else {
        capitalize(core)
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn fallback_app_title(app: &str) -> String {
    app.split(['.', '-', '_'])
        .filter(|t| t.len() >= 4 && !["com", "org", "android", "harbour", "mobile", "client", "mediaclient", "app"].contains(t))
        .map(capitalize)
        .next()
        .unwrap_or_else(|| app.to_string())
}

fn desktop_dirs() -> Vec<PathBuf> {
    vec![home().join(".local/share/applications"), PathBuf::from("/usr/share/applications")]
}

fn app_display_name(app: &str) -> Option<String> {
    let apkd_prefix = format!("apkd_launcher_{}-", app.replace('.', "_"));
    let exec_marker = format!(" {app}/");
    for dir in desktop_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for f in rd.flatten() {
            let path = f.path();
            if path.extension().is_none_or(|e| e != "desktop") {
                continue;
            }
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
            let by_name = stem == app || stem == format!("harbour-{app}") || stem.starts_with(&apkd_prefix);
            let Ok(content) = std::fs::read_to_string(&path) else { continue };
            if by_name || content.lines().any(|l| l.starts_with("Exec=") && l.contains(&exec_marker)) {
                if let Some(name) = desktop_name(&content) {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// `Name[fr]=` en priorité, sinon `Name=` (section [Desktop Entry]).
fn desktop_name(content: &str) -> Option<String> {
    let mut in_entry = false;
    let (mut fr, mut plain) = (None, None);
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some(v) = line.strip_prefix("Name[fr]=") {
            fr = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Name=") {
            plain = Some(v.trim().to_string());
        }
    }
    fr.or(plain).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles_from_origins() {
        assert_eq!(suggest_title("https://compte.laposte.fr/login"), "Laposte");
        assert_eq!(suggest_title("https://www.bbc.co.uk/"), "BBC");
        assert_eq!(fallback_app_title("com.netflix.mediaclient"), "Netflix");
        assert_eq!(desktop_name("[Desktop Entry]\nName=Mail\nName[fr]=Courriel\n"), Some("Courriel".into()));
        assert_eq!(suggest_title(""), "");
    }
}
