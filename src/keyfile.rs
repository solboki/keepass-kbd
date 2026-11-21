//! Fichiers clés KeePass : lecture et création au format XML 2.0 (KeePass 2.47+,
//! KeePassXC, KeePassDX) : 32 octets aléatoires en hexadécimal, avec l'empreinte de contrôle.

use std::io::Write;
use std::path::Path;

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Contenu d'un fichier clé, lu en mémoire (n'importe quel format reconnu par KeePass).
pub fn read(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|e| crate::i18n::tr1("key file unreadable (%1)", &format!("{}: {e}", path.display())))
}

/// Texte d'un fichier clé XML 2.0 pour la clé donnée.
fn xml(key: &[u8]) -> Zeroizing<String> {
    let hex: String = key.iter().map(|b| format!("{b:02X}")).collect();
    let groups: Vec<&str> = (0..hex.len()).step_by(8).map(|i| &hex[i..(i + 8).min(hex.len())]).collect();
    let hash: String = Sha256::digest(key)[..4].iter().map(|b| format!("{b:02X}")).collect();
    let half = groups.len() / 2;
    Zeroizing::new(format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n\t\t<Data Hash=\"{hash}\">\n\t\t\t{}\n\t\t\t{}\n\t\t</Data>\n\t</Key>\n</KeyFile>\n",
        groups[..half].join(" "),
        groups[half..].join(" "),
    ))
}

/// Crée un nouveau fichier clé (refuse d'écraser un fichier existant ; lisible par vous seul).
pub fn create(path: &Path) -> Result<(), String> {
    let mut key = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *key);
    let text = xml(&*key);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_private()
        .open(path)
        .map_err(|e| crate::i18n::tr1("cannot create the file (%1)", &format!("{}: {e}", path.display())))?;
    f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| e.to_string())
}

/// Ouverture avec les droits 0600 (fichier clé, base : lisibles par l'utilisateur seul).
pub trait PrivateMode {
    fn mode_private(&mut self) -> &mut Self;
}

impl PrivateMode for std::fs::OpenOptions {
    fn mode_private(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::{Database, DatabaseKey};

    #[test]
    fn hash_matches_the_keepass_example() {
        // Exemple de la documentation KeePass (et des tests de keepass-rs).
        let key: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&"36057B1C35037FD962257893C0A22403EE3F8FBB504D998108B821CB00D28F89"[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        let text = xml(&key);
        assert!(text.contains("<Data Hash=\"A65F0C2D\">"), "{}", *text);
        assert!(text.contains("36057B1C 35037FD9 62257893 C0A22403\n"));
        assert!(text.contains("EE3F8FBB 504D9981 08B821CB 00D28F89\n"));
    }

    #[test]
    fn created_key_file_opens_a_database() {
        let dir = std::env::temp_dir().join(format!("keepass-kbd-kf-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cle.keyx");
        create(&path).unwrap();
        assert!(create(&path).is_err(), "ne doit pas écraser");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let bytes = read(&path).unwrap();
        let key = || DatabaseKey::new().with_keyfile(&mut &bytes[..]).unwrap();
        let mut out = Vec::new();
        Database::new().save(&mut out, key()).unwrap();
        assert!(Database::parse(&out, key()).is_ok());
        // Une autre clé ne l'ouvre pas.
        let other = dir.join("autre.keyx");
        create(&other).unwrap();
        let other = read(&other).unwrap();
        assert!(Database::parse(&out, DatabaseKey::new().with_keyfile(&mut &other[..]).unwrap()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
