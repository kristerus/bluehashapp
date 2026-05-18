//! Tauri build script. In addition to the standard `tauri_build::build()`
//! call, rasterizes `icons/source.svg` (the BlueHash key glyph) into:
//!
//!   * `icons/icon.ico` - multi-size (16/32/48/64/256), embedded into the
//!     Windows .exe resource section by Tauri's build pipeline.
//!   * `icons/icon.png` - 256×256, used as the system-tray glyph.
//!
//! Re-runs only when the SVG (or this file) changes. Falls back to a
//! solid-blue placeholder if `source.svg` is missing, so a fresh clone
//! still compiles before any branding work.

use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use std::path::Path;

const ACCENT_R: u8 = 0x3B;
const ACCENT_G: u8 = 0x82;
const ACCENT_B: u8 = 0xF6;

const ICO_SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256];
const TRAY_PNG_SIZE: u32 = 256;

fn main() {
    create_dir_all("icons").expect("create icons dir");
    println!("cargo:rerun-if-changed=icons/source.svg");
    println!("cargo:rerun-if-changed=build.rs");

    let png_path = Path::new("icons/icon.png");
    let ico_path = Path::new("icons/icon.ico");
    let svg_path = Path::new("icons/source.svg");

    if svg_path.exists() {
        match render_from_svg(svg_path, png_path, ico_path) {
            Ok(()) => {}
            Err(e) => {
                println!("cargo:warning=SVG rasterize failed ({e}); falling back to placeholder");
                write_png_placeholder(png_path, TRAY_PNG_SIZE);
                write_ico_placeholder(ico_path);
            }
        }
    } else {
        if !png_path.exists() { write_png_placeholder(png_path, TRAY_PNG_SIZE); }
        if !ico_path.exists() { write_ico_placeholder(ico_path); }
    }

    tauri_build::build();
}

// ---------- SVG → raster ----------

fn render_from_svg(
    svg_path: &Path,
    png_path: &Path,
    ico_path: &Path,
) -> Result<(), String> {
    let svg_data = std::fs::read(svg_path).map_err(|e| format!("read svg: {e}"))?;
    let opt = usvg::Options::default();
    let tree = usvg::Tree::from_data(&svg_data, &opt)
        .map_err(|e| format!("parse svg: {e}"))?;

    // Rasterize one pixmap per ICO size, plus the tray PNG.
    let mut ico_dir = ico::IconDir::new(ico::ResourceType::Icon);
    for &sz in ICO_SIZES {
        let rgba = rasterize(&tree, sz)?;
        let img = ico::IconImage::from_rgba_data(sz, sz, rgba);
        ico_dir.add_entry(ico::IconDirEntry::encode(&img)
            .map_err(|e| format!("encode ico {sz}: {e}"))?);
    }
    let ico_file = File::create(ico_path).map_err(|e| format!("create {ico_path:?}: {e}"))?;
    ico_dir.write(ico_file).map_err(|e| format!("write ico: {e}"))?;

    let tray_rgba = rasterize(&tree, TRAY_PNG_SIZE)?;
    write_png_rgba(png_path, TRAY_PNG_SIZE, &tray_rgba);

    Ok(())
}

fn rasterize(tree: &usvg::Tree, size: u32) -> Result<Vec<u8>, String> {
    let mut pixmap = tiny_skia::Pixmap::new(size, size)
        .ok_or_else(|| format!("pixmap {size}"))?;
    let tree_size = tree.size();
    let scale = (size as f32 / tree_size.width()).min(size as f32 / tree_size.height());
    // Centre the rendered tree inside the square pixmap.
    let tx = (size as f32 - tree_size.width() * scale) / 2.0;
    let ty = (size as f32 - tree_size.height() * scale) / 2.0;
    let transform = tiny_skia::Transform::from_scale(scale, scale).post_translate(tx, ty);
    resvg::render(tree, transform, &mut pixmap.as_mut());
    Ok(pixmap.data().to_vec())
}

fn write_png_rgba(path: &Path, size: u32, rgba: &[u8]) {
    let file = File::create(path).expect("create icon.png");
    let w = BufWriter::new(file);
    let mut encoder = png::Encoder::new(w, size, size);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().expect("png header");
    writer.write_image_data(rgba).expect("png data");
}

// ---------- placeholder (no SVG / SVG broken) ----------

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

fn write_png_placeholder(path: &Path, size: u32) {
    write_png_rgba(path, size, &rgba_block(size));
}

fn write_ico_placeholder(path: &Path) {
    let mut dir = ico::IconDir::new(ico::ResourceType::Icon);
    for &sz in &[16u32, 32, 48, 64, 256] {
        let image = ico::IconImage::from_rgba_data(sz, sz, rgba_block(sz));
        dir.add_entry(ico::IconDirEntry::encode(&image).expect("encode ico"));
    }
    let file = File::create(path).expect("create icon.ico");
    dir.write(file).expect("write ico");
}
