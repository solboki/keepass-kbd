//! Codes à usage unique (TOTP, RFC 6238) des entrées KeePass.
//!
//! Formats reconnus :
//! - champ `otp` contenant une URI `otpauth://totp/…?secret=…` (KeePassXC, KeePassDX, KeePassRX) ;
//! - champs natifs de KeePass 2.47+ : `TimeOtp-Secret-Base32` (ou `-Secret`, `-Secret-Hex`,
//!   `-Secret-Base64`), `TimeOtp-Length`, `TimeOtp-Period`, `TimeOtp-Algorithm` ;
//! - ancien format KeePassXC : `TOTP Seed` + `TOTP Settings` (« 30;6 », « 30;S » pour Steam).
//!
//! La clé secrète ne quitte jamais le service : seul le code calculé est transmis.

use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub struct Spec {
    secret: Zeroizing<Vec<u8>>,
    pub period: u64,
    pub digits: u32,
    pub algorithm: Algorithm,
    pub steam: bool,
}

const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

impl Spec {
    /// Lit la configuration TOTP d'une entrée ; `get` renvoie la valeur d'un champ.
    pub fn from_fields<'a>(get: impl Fn(&str) -> Option<&'a str>) -> Option<Spec> {
        let present = |k: &str| get(k).map(str::trim).filter(|v| !v.is_empty());
        if let Some(v) = present("otp") {
            return parse_uri(v).or_else(|| Spec::new(decode_base32(v)?, 30, 6, Algorithm::Sha1, false));
        }
        let secret = present("TimeOtp-Secret-Base32")
            .and_then(decode_base32)
            .or_else(|| present("TimeOtp-Secret-Hex").and_then(decode_hex))
            .or_else(|| present("TimeOtp-Secret-Base64").and_then(decode_base64))
            .or_else(|| present("TimeOtp-Secret").map(|s| Zeroizing::new(s.as_bytes().to_vec())));
        if let Some(secret) = secret {
            let digits = present("TimeOtp-Length").and_then(|v| v.parse().ok()).unwrap_or(6);
            let period = present("TimeOtp-Period").and_then(|v| v.parse().ok()).unwrap_or(30);
            let algorithm = match present("TimeOtp-Algorithm").map(|a| a.to_uppercase().replace(['-', '_'], "")) {
                Some(a) if a.ends_with("SHA256") => Algorithm::Sha256,
                Some(a) if a.ends_with("SHA512") => Algorithm::Sha512,
                _ => Algorithm::Sha1,
            };
            return Spec::new(secret, period, digits, algorithm, false);
        }
        let seed = present("TOTP Seed").and_then(decode_base32)?;
        let (mut period, mut digits, mut steam) = (30, 6, false);
        if let Some(settings) = present("TOTP Settings") {
            let mut parts = settings.split(';').map(str::trim);
            if let Some(p) = parts.next().and_then(|p| p.parse().ok()) {
                period = p;
            }
            match parts.next() {
                Some("S") => steam = true,
                Some(d) => digits = d.parse().unwrap_or(6),
                None => {}
            }
        }
        Spec::new(seed, period, digits, Algorithm::Sha1, steam)
    }

    fn new(secret: Zeroizing<Vec<u8>>, period: u64, digits: u32, algorithm: Algorithm, steam: bool) -> Option<Spec> {
        if secret.is_empty() || period == 0 || !(1..=10).contains(&digits) {
            return None;
        }
        let digits = if steam { 5 } else { digits };
        Some(Spec { secret, period, digits, algorithm, steam })
    }

    /// Code valable à l'instant `unix` (secondes) et nombre de secondes restantes.
    pub fn code_at(&self, unix: u64) -> (String, u64) {
        let counter = unix / self.period;
        let mac = hmac(self.algorithm, &self.secret, &counter.to_be_bytes());
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;
        let bin = u32::from_be_bytes([mac[offset] & 0x7f, mac[offset + 1], mac[offset + 2], mac[offset + 3]]);
        let code = if self.steam {
            let mut v = bin as usize;
            (0..5)
                .map(|_| {
                    let c = STEAM_CHARS[v % STEAM_CHARS.len()] as char;
                    v /= STEAM_CHARS.len();
                    c
                })
                .collect()
        } else {
            let modulo = 10u64.pow(self.digits);
            format!("{:0width$}", bin as u64 % modulo, width = self.digits as usize)
        };
        (code, self.period - unix % self.period)
    }

    pub fn code_now(&self) -> (String, u64) {
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.code_at(unix)
    }
}

fn parse_uri(uri: &str) -> Option<Spec> {
    let rest = uri.strip_prefix("otpauth://").or_else(|| uri.strip_prefix("OTPAUTH://"))?;
    let (kind, rest) = rest.split_once('/')?;
    if !kind.eq_ignore_ascii_case("totp") {
        return None; // HOTP (compteur) non géré : il faudrait réécrire la base à chaque code.
    }
    let query = rest.split_once('?').map(|(_, q)| q).unwrap_or("");
    let (mut secret, mut period, mut digits, mut algorithm, mut steam) = (None, 30, 6, Algorithm::Sha1, false);
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let v = percent_decode(v);
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret = decode_base32(&v),
            "period" => period = v.parse().ok()?,
            "digits" => digits = v.parse().ok()?,
            "algorithm" => {
                algorithm = match v.to_uppercase().replace('-', "").as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    _ => return None,
                }
            }
            "encoder" => steam = v.eq_ignore_ascii_case("steam"),
            _ => {}
        }
    }
    Spec::new(secret?, period, digits, algorithm, steam)
}

fn percent_decode(s: &str) -> Zeroizing<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => match s.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(h, 16).ok()) {
                Some(v) => {
                    out.push(v);
                    i += 3;
                    continue;
                }
                None => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&out).into_owned())
}

pub fn decode_base32(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.chars() {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            ' ' | '-' | '=' => continue,
            _ => return None,
        };
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn decode_hex(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(s.len() / 2));
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(s.get(i..i + 2)?, 16).ok()?);
    }
    Some(out)
}

fn decode_base64(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\n' | b'\r' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (!out.is_empty()).then_some(out)
}

fn hash(algorithm: Algorithm, parts: &[&[u8]]) -> Vec<u8> {
    match algorithm {
        Algorithm::Sha1 => {
            use sha1::Digest;
            let mut h = sha1::Sha1::new();
            parts.iter().for_each(|p| h.update(p));
            h.finalize().to_vec()
        }
        Algorithm::Sha256 => {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            parts.iter().for_each(|p| h.update(p));
            h.finalize().to_vec()
        }
        Algorithm::Sha512 => {
            use sha2::Digest;
            let mut h = sha2::Sha512::new();
            parts.iter().for_each(|p| h.update(p));
            h.finalize().to_vec()
        }
    }
}

/// HMAC (RFC 2104).
fn hmac(algorithm: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let block = if algorithm == Algorithm::Sha512 { 128 } else { 64 };
    let mut k = Zeroizing::new(if key.len() > block { hash(algorithm, &[key]) } else { key.to_vec() });
    k.resize(block, 0);
    let ipad: Zeroizing<Vec<u8>> = Zeroizing::new(k.iter().map(|b| b ^ 0x36).collect());
    let opad: Zeroizing<Vec<u8>> = Zeroizing::new(k.iter().map(|b| b ^ 0x5c).collect());
    let inner = hash(algorithm, &[&ipad, msg]);
    hash(algorithm, &[&opad, &inner])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn spec(fields: &[(&str, &str)]) -> Option<Spec> {
        let m: HashMap<String, String> = fields.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Spec::from_fields(|k| m.get(k).map(|s| s.as_str()))
    }

    // Vecteurs de la RFC 6238, annexe B (clés ASCII « 1234567890… »).
    const K20: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const K32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    const K64: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";

    #[test]
    fn rfc6238_vectors() {
        let cases = [
            (59u64, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1234567890, "89005924", "91819424", "93441116"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, s1, s256, s512) in cases {
            let a = spec(&[("otp", &format!("otpauth://totp/x?secret={K20}&digits=8"))]).unwrap();
            assert_eq!(a.code_at(t).0, s1);
            let b = spec(&[("otp", &format!("otpauth://totp/x?secret={K32}&digits=8&algorithm=SHA256"))]).unwrap();
            assert_eq!(b.code_at(t).0, s256);
            let c = spec(&[("otp", &format!("otpauth://totp/x?secret={K64}&digits=8&algorithm=SHA512"))]).unwrap();
            assert_eq!(c.code_at(t).0, s512);
        }
    }

    #[test]
    fn formats() {
        let uri = spec(&[("otp", &format!("otpauth://totp/Site%3Aboris?secret={}&issuer=Site", K20.to_lowercase()))]).unwrap();
        assert_eq!(uri.code_at(59), ("287082".to_string(), 1));
        let kp2 = spec(&[("TimeOtp-Secret-Base32", K20)]).unwrap();
        assert_eq!(kp2.code_at(59).0, "287082");
        let kp2_utf8 = spec(&[("TimeOtp-Secret", "12345678901234567890"), ("TimeOtp-Length", "8")]).unwrap();
        assert_eq!(kp2_utf8.code_at(59).0, "94287082");
        let kp2_hex = spec(&[("TimeOtp-Secret-Hex", "3132333435363738393031323334353637383930")]).unwrap();
        assert_eq!(kp2_hex.code_at(59).0, "287082");
        let kp2_b64 = spec(&[("TimeOtp-Secret-Base64", "MTIzNDU2Nzg5MDEyMzQ1Njc4OTA="), ("TimeOtp-Algorithm", "HMAC-SHA-1")]).unwrap();
        assert_eq!(kp2_b64.code_at(59).0, "287082");
        let legacy = spec(&[("TOTP Seed", K20), ("TOTP Settings", "30;8")]).unwrap();
        assert_eq!(legacy.code_at(59).0, "94287082");
        let steam = spec(&[("TOTP Seed", K20), ("TOTP Settings", "30;S")]).unwrap();
        assert_eq!(steam.code_at(59).0.len(), 5);
        assert!(steam.code_at(59).0.bytes().all(|c| STEAM_CHARS.contains(&c)));
        let raw = spec(&[("otp", "JBSW Y3DP EHPK 3PXP")]).unwrap();
        assert_eq!(raw.digits, 6);
        assert_eq!(raw.code_at(100).1, 20);
    }

    #[test]
    fn rejected() {
        assert!(spec(&[]).is_none());
        assert!(spec(&[("otp", "")]).is_none());
        assert!(spec(&[("otp", "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")]).is_none());
        assert!(spec(&[("otp", "otpauth://totp/x?issuer=nosecret")]).is_none());
        assert!(spec(&[("otp", "not base32 !")]).is_none());
        assert!(spec(&[("otp", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")]).is_none());
    }
}
