//! Lecture des QR codes (« flashcodes ») de double authentification dans une image :
//! capture d'écran du site, ou photo prise depuis la page des Paramètres.

use std::path::Path;

use image::{imageops::FilterType, DynamicImage, GrayImage};
use zeroize::Zeroizing;

/// Au-delà, l'image est réduite avant la recherche (photos de l'appareil : 12 Mpx et plus).
const MAX_SIDE: u32 = 2000;

/// Contenus des QR codes trouvés dans le fichier image (PNG ou JPEG).
pub fn decode_file(path: &Path) -> Result<Vec<Zeroizing<String>>, String> {
    let img = image::ImageReader::open(path)
        .and_then(|r| r.with_guessed_format())
        .map_err(|e| e.to_string())?
        .decode()
        .map_err(|e| e.to_string())?;
    Ok(decode_image(&img))
}

pub fn decode_image(img: &DynamicImage) -> Vec<Zeroizing<String>> {
    let gray = img.to_luma8();
    let gray = if gray.width().max(gray.height()) > MAX_SIDE {
        let r = MAX_SIDE as f32 / gray.width().max(gray.height()) as f32;
        image::imageops::resize(&gray, (gray.width() as f32 * r) as u32, (gray.height() as f32 * r) as u32, FilterType::Triangle)
    } else {
        gray
    };
    let found = decode_gray(&gray);
    if !found.is_empty() {
        return found;
    }
    // Code très petit dans une grande capture, ou modules trop fins : nouvel essai agrandi.
    if gray.width().max(gray.height()) <= MAX_SIDE / 2 {
        let big = image::imageops::resize(&gray, gray.width() * 2, gray.height() * 2, FilterType::Nearest);
        return decode_gray(&big);
    }
    Vec::new()
}

fn decode_gray(gray: &GrayImage) -> Vec<Zeroizing<String>> {
    let mut prepared = rqrr::PreparedImage::prepare(gray.clone());
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|g| g.decode().ok().map(|(_, content)| Zeroizing::new(content)))
        .collect()
}

/// Premier contenu de type otpauth (TOTP, HOTP ou export Google Authenticator), sinon le premier.
pub fn pick_otp(contents: &[Zeroizing<String>]) -> Option<&str> {
    contents
        .iter()
        .find(|c| c.trim().to_ascii_lowercase().starts_with("otpauth"))
        .or_else(|| contents.first())
        .map(|c| c.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GenericImage, Luma};

    fn qr_image(text: &str, module: u32) -> GrayImage {
        qrcode::QrCode::new(text.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .module_dimensions(module, module)
            .build()
    }

    #[test]
    fn reads_a_qr_code_inside_a_screenshot() {
        let uri = "otpauth://totp/Amazon:boris@example.org?secret=JBSWY3DPEHPK3PXP&issuer=Amazon";
        let code = qr_image(uri, 6);
        // Fausse capture d'écran : fond gris clair, QR code au milieu.
        let mut shot = GrayImage::from_pixel(1032, 2272, Luma([235]));
        shot.copy_from(&code, 200, 700).unwrap();
        let found = decode_image(&DynamicImage::ImageLuma8(shot));
        assert_eq!(pick_otp(&found), Some(uri));
    }

    #[test]
    fn reads_a_large_photo_after_downscaling() {
        let uri = "otpauth://totp/GitHub:boris?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let code = qr_image(uri, 40);
        let mut photo = GrayImage::from_pixel(4000, 3000, Luma([200]));
        photo.copy_from(&code, 1200, 600).unwrap();
        let found = decode_image(&DynamicImage::ImageLuma8(photo));
        assert_eq!(pick_otp(&found), Some(uri));
    }

    #[test]
    fn reads_png_and_jpeg_files() {
        let uri = "otpauth://totp/Site:boris?secret=JBSWY3DPEHPK3PXP&issuer=Site";
        let dir = std::env::temp_dir().join(format!("keepass-kbd-qr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut shot = GrayImage::from_pixel(800, 1400, Luma([250]));
        shot.copy_from(&qr_image(uri, 8), 150, 400).unwrap();
        for name in ["capture.png", "photo.jpg"] {
            let path = dir.join(name);
            shot.save(&path).unwrap();
            if let Ok(out) = std::env::var("KPX_QR_SAMPLE_DIR") {
                let _ = std::fs::copy(&path, Path::new(&out).join(name));
            }
            assert_eq!(pick_otp(&decode_file(&path).unwrap()), Some(uri), "{name}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(decode_file(Path::new("/nonexistent.png")).is_err());
    }

    #[test]
    fn prefers_the_otp_code_and_finds_nothing_in_a_blank_image() {
        let contents = vec![Zeroizing::new("https://example.org".to_string()), Zeroizing::new("otpauth://totp/x".to_string())];
        assert_eq!(pick_otp(&contents), Some("otpauth://totp/x"));
        let blank = GrayImage::from_pixel(500, 500, Luma([255]));
        assert!(decode_image(&DynamicImage::ImageLuma8(blank)).is_empty());
    }
}
