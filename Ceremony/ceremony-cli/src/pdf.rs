//! PDF rendering of keyholder booklets — a print-ready companion to the
//! `.txt` booklets. Each share line becomes an entry: a **bold** date +
//! window id, then the 14 words set fully justified to the column width.
//! Three columns per page, narrow side margins, and a generous top margin so
//! a stapled booklet's binding never bites into the text.
//!
//! The font is DejaVu Sans Mono, vendored next to this file and embedded into
//! every PDF — open-licensed, self-contained, and dense on the page. It is
//! monospaced, so columns of dates line up and the words pack tightly. The
//! upright face sets the words; its bold companion sets the date/window-id
//! header.

use anyhow::{Context, Result};
use owned_ttf_parser::{AsFaceRef, OwnedFace};
use printpdf::{IndirectFontRef, Mm, PdfDocument, PdfLayerReference};
use std::fs;
use std::io::BufWriter;
use std::path::Path;

/// Vendored, open-licensed, monospaced — embedded into every booklet PDF.
const FONT_TTF: &[u8] = include_bytes!("../assets/fonts/DejaVuSansMono.ttf");
const FONT_BOLD_TTF: &[u8] = include_bytes!("../assets/fonts/DejaVuSansMono-Bold.ttf");

// --- page geometry (US Letter), all in millimetres ----------------------
const PAGE_W: f32 = 215.9;
const PAGE_H: f32 = 279.4;
const SIDE_MARGIN: f32 = 10.0; // narrow sides
const TOP_MARGIN: f32 = 24.0; // room for a staple + the running header
const BOT_MARGIN: f32 = 12.0;
const GUTTER: f32 = 6.0; // space between columns
const COLS: usize = 3;
const BODY_PT: f32 = 8.0; // dense body type
const TITLE_PT: f32 = 11.0; // "SplitKey share k/n for <community>"
const SUB_PT: f32 = 7.0; // epoch / range / page sub-line
const LINE_H: f32 = 3.5; // body leading (dense)
const ENTRY_GAP: f32 = 1.8; // blank space between entries

fn col_width() -> f32 {
    (PAGE_W - 2.0 * SIDE_MARGIN - (COLS as f32 - 1.0) * GUTTER) / COLS as f32
}
fn col_x(col: usize) -> f32 {
    SIDE_MARGIN + col as f32 * (col_width() + GUTTER)
}
/// Baseline of the first body line in a column.
fn col_top() -> f32 {
    PAGE_H - TOP_MARGIN
}

/// The booklet font family: a parsed upright face for word metrics. (DejaVu
/// Sans Mono is monospaced, so the bold face shares these advances — one set
/// of metrics drives both wrapping and justification.)
pub struct LoadedFont {
    face: OwnedFace,
}

impl LoadedFont {
    /// Advance width of `ch` at `size_pt`, in millimetres.
    fn char_w(&self, ch: char, size_pt: f32) -> f32 {
        let f = self.face.as_face_ref();
        let upem = f.units_per_em() as f32;
        let adv = f
            .glyph_index(ch)
            .and_then(|g| f.glyph_hor_advance(g))
            .unwrap_or(upem as u16) as f32;
        adv / upem * size_pt * 25.4 / 72.0
    }

    fn text_w(&self, s: &str, size_pt: f32) -> f32 {
        s.chars().map(|c| self.char_w(c, size_pt)).sum()
    }
}

/// Parse the vendored upright font for metrics. Infallible in practice (the
/// TTF is compiled in), but a corrupt embed surfaces here, not mid-render.
pub fn load_font() -> Result<LoadedFont> {
    let face = OwnedFace::from_vec(FONT_TTF.to_vec(), 0)
        .map_err(|e| anyhow::anyhow!("embedded booklet font is unusable: {e}"))?;
    Ok(LoadedFont { face })
}

/// One share line: a bold date + window tag, then 14 words.
pub struct Entry {
    pub date: String,
    pub tag: String,
    pub words: String,
}

/// Identifying metadata for the running header.
pub struct BookletMeta<'a> {
    pub community: &'a str,
    pub epoch: u16,
    pub holder: &'a str,
    pub share_idx: usize, // 1-based
    pub n: usize,
    pub threshold: u8,
    pub window_hours: u32,
    pub first_label: &'a str,
    pub last_label: &'a str,
}

/// Pre-laid-out entry: header parts + word lines wrapped to the column.
struct Laid {
    date: String,
    tag: String,
    lines: Vec<Vec<String>>,
}

impl Laid {
    fn height(&self) -> f32 {
        (1 + self.lines.len()) as f32 * LINE_H + ENTRY_GAP
    }
}

/// Greedy word wrap of `words` to `col_w` using the font metrics.
fn wrap(words: &str, font: &LoadedFont, col_w: f32) -> Vec<Vec<String>> {
    let space = font.char_w(' ', BODY_PT);
    let mut lines: Vec<Vec<String>> = Vec::new();
    let mut cur: Vec<String> = Vec::new();
    let mut cur_w = 0.0f32;
    for word in words.split_whitespace() {
        let ww = font.text_w(word, BODY_PT);
        let tentative = if cur.is_empty() { ww } else { cur_w + space + ww };
        if cur.is_empty() || tentative <= col_w {
            cur_w = tentative;
            cur.push(word.to_string());
        } else {
            lines.push(std::mem::take(&mut cur));
            cur = vec![word.to_string()];
            cur_w = ww;
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

pub fn write_booklet_pdf(
    path: &Path,
    meta: &BookletMeta,
    entries: &[Entry],
    font: &LoadedFont,
) -> Result<()> {
    let col_w = col_width();
    let laid: Vec<Laid> = entries
        .iter()
        .map(|e| Laid {
            date: e.date.clone(),
            tag: e.tag.clone(),
            lines: wrap(&e.words, font, col_w),
        })
        .collect();

    let (doc, page, layer) =
        PdfDocument::new(format!("SplitKey booklet — {}", meta.holder), Mm(PAGE_W), Mm(PAGE_H), "L");
    let font_ref = doc
        .add_external_font(FONT_TTF)
        .map_err(|e| anyhow::anyhow!("embed booklet font: {e}"))?;
    let bold_ref = doc
        .add_external_font(FONT_BOLD_TTF)
        .map_err(|e| anyhow::anyhow!("embed booklet bold font: {e}"))?;

    let mut cur = doc.get_page(page).get_layer(layer);
    let mut page_no = 1usize;
    draw_page_header(&cur, meta, &font_ref, &bold_ref, page_no);

    let mut col = 0usize;
    let mut y = col_top();

    for item in &laid {
        // Keep an entry whole: drop to the next column/page if it won't fit
        // (but never bounce an entry off a fresh, full-height column).
        if y - item.height() < BOT_MARGIN && y < col_top() {
            col += 1;
            if col >= COLS {
                let (np, nl) = doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "L");
                cur = doc.get_page(np).get_layer(nl);
                page_no += 1;
                draw_page_header(&cur, meta, &font_ref, &bold_ref, page_no);
                col = 0;
            }
            y = col_top();
        }
        let x = col_x(col);

        // Header line: bold date, then bold window tag.
        cur.use_text(&item.date, BODY_PT, Mm(x), Mm(y), &bold_ref);
        let dx = x + font.text_w(&item.date, BODY_PT) + font.char_w(' ', BODY_PT);
        cur.use_text(&item.tag, BODY_PT, Mm(dx), Mm(y), &bold_ref);
        y -= LINE_H;

        // Word lines: justified, except the last line of the entry.
        let last = item.lines.len() - 1;
        for (li, line) in item.lines.iter().enumerate() {
            draw_words(&cur, font, &font_ref, line, x, y, li != last);
            y -= LINE_H;
        }
        y -= ENTRY_GAP;
    }

    let f = fs::File::create(path).with_context(|| path.display().to_string())?;
    doc.save(&mut BufWriter::new(f)).map_err(|e| anyhow::anyhow!("write pdf: {e}"))?;
    Ok(())
}

/// Place `words` at baseline `y`. When `justify`, stretch the inter-word gaps
/// so the line fills `col_w`; otherwise set them at a single space.
fn draw_words(
    layer: &PdfLayerReference,
    font: &LoadedFont,
    font_ref: &IndirectFontRef,
    words: &[String],
    x: f32,
    y: f32,
    justify: bool,
) {
    let widths: Vec<f32> = words.iter().map(|w| font.text_w(w, BODY_PT)).collect();
    let space = font.char_w(' ', BODY_PT);
    let gap = if justify && words.len() > 1 {
        let total: f32 = widths.iter().sum();
        ((col_width() - total) / (words.len() - 1) as f32).max(space)
    } else {
        space
    };
    let mut cx = x;
    for (i, w) in words.iter().enumerate() {
        layer.use_text(w, BODY_PT, Mm(cx), Mm(y), font_ref);
        cx += widths[i] + gap;
    }
}

/// Two lines in the top margin (above the columns, below the staple): a plain
/// human title so a stray sheet is identifiable, then the ceremony detail.
fn draw_page_header(
    layer: &PdfLayerReference,
    meta: &BookletMeta,
    font_ref: &IndirectFontRef,
    bold_ref: &IndirectFontRef,
    page_no: usize,
) {
    let title = format!(
        "SplitKey share {idx}/{n} for {community} — holder {holder}",
        idx = meta.share_idx,
        n = meta.n,
        community = meta.community,
        holder = meta.holder,
    );
    layer.use_text(title, TITLE_PT, Mm(SIDE_MARGIN), Mm(PAGE_H - 12.0), bold_ref);

    let sub = format!(
        "epoch {epoch} · threshold {t} · {hours}h UTC {first}..{last} · page {page}",
        epoch = meta.epoch,
        t = meta.threshold,
        hours = meta.window_hours,
        first = meta.first_label,
        last = meta.last_label,
        page = page_no,
    );
    layer.use_text(sub, SUB_PT, Mm(SIDE_MARGIN), Mm(PAGE_H - 16.5), font_ref);
}
