//! Tauri build script. In addition to the standard `tauri_build::build()`
//! call, ensures `icons/icon.ico` and `icons/icon.png` exist — Tauri 1.x
//! on Windows requires the .ico for resource embedding into the binary,
//! and our tauri.conf.json points the tray glyph at the .png.
//!
//! The generated files are solid-blue placeholders (BlueHash accent
//! `#3B82F6`). Janos should swap them out for the real logo before any
//! production bundle is shipped.

use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use std::path::Path;

const ACCENT_R: u8 = 0x3B;
const ACCENT_G: u8 = 0x82;
const ACCENT_B: u8 = 0xF6;

fn main() {
    ensure_icons();
    tauri_build::build();
}

fn ensure_icons() {
    create_dir_all("icons").expect("create icons dir");

    let png_path = Path::new("icons/icon.png");
    let ico_path = Path::new("icons/icon.ico");

    if !png_path.exists() {
        write_png(png_path, 32);
    }
    if !ico_path.exists() {
        write_ico(ico_path, 32);
    }
}

fn rgba_block(size: u32) -> Vec<u8> {
    let n = (size * size * 4) as usize;
    let mut buf = vec![0u8; n];
    for chunk in buf.chunks_exact_mut(4) {
        chunk[0] = ACCENT_R;
        chunk[1] = ACCENT_G;
        chunk[2] = ACCENT_B;
        chunk[3] = 0xFF;
    }
    buf
}

fn write_png(path: &Path, size: u32) {
    let file = File::create(path).expect("create icon.png");
    let w = BufWriter::new(file);
    let mut encoder = png::Encoder::new(w, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("png header");
    writer
        .write_image_data(&rgba_block(size))
        .expect("png data");
}

fn write_ico(path: &Path, size: u32) {
    let image = ico::IconImage::from_rgba_data(size, size, rgba_block(size));
    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    dir.add_entry(ico::IconDirEntry::encode(&image).expect("encode ico"));
    let file = File::create(path).expect("create icon.ico");
    dir.write(file).expect("write ico");
}
