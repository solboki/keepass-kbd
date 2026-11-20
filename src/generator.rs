//! Générateur de mots de passe (CSPRNG de `rand`, réensemencé par le système).

use rand::seq::{IndexedRandom, SliceRandom};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
const AMBIGUOUS: &str = "Il1O0o|";

/// `classes` : `l` minuscules, `u` majuscules, `d` chiffres, `s` symboles,
/// `a` pour exclure les caractères ambigus. Au moins un caractère de chaque classe choisie.
pub fn generate(length: usize, classes: &str) -> Result<String, String> {
    let exclude_ambiguous = classes.contains('a');
    let mut sets: Vec<Vec<char>> = Vec::new();
    for (flag, chars) in [('l', LOWER), ('u', UPPER), ('d', DIGITS), ('s', SYMBOLS)] {
        if classes.contains(flag) {
            let set: Vec<char> = chars
                .chars()
                .filter(|c| !exclude_ambiguous || !AMBIGUOUS.contains(*c))
                .collect();
            sets.push(set);
        }
    }
    if sets.is_empty() {
        return Err("aucune classe de caractères choisie".into());
    }
    if length < sets.len() || length > 256 {
        return Err(format!("longueur invalide (entre {} et 256)", sets.len()));
    }
    let mut rng = rand::rng();
    let all: Vec<char> = sets.iter().flatten().copied().collect();
    let mut out: Vec<char> = sets.iter().map(|s| *s.choose(&mut rng).unwrap()).collect();
    while out.len() < length {
        out.push(*all.choose(&mut rng).unwrap());
    }
    out.shuffle(&mut rng);
    Ok(out.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_length_and_classes() {
        for _ in 0..200 {
            let p = generate(12, "luds").unwrap();
            assert_eq!(p.chars().count(), 12);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
        let p = generate(64, "luda").unwrap();
        assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        assert!(generate(2, "luds").is_err());
        assert!(generate(10, "").is_err());
    }
}
