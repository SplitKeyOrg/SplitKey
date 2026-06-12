//! Booklet *line* format — shared between the ceremony writer and the
//! keeper parser so the contract lives in one place:
//!
//! ```text
//! 2026-07-09  w20643  acoustic above embrace … jealous
//! ```
//!
//! date label, `w<window_index>`, 14 words. Header lines (anything that
//! doesn't match) are ignored by the parser.

use crate::{dates, WORDS_PER_LINE};

pub fn format_line(window: u64, window_secs: u32, words: &str) -> String {
    format!("{}  w{}  {}", dates::label_for_window(window, window_secs), window, words)
}

/// Find the share line for `window` in a booklet; returns the words part.
pub fn find_line(booklet: &str, window: u64) -> Option<String> {
    let tag = format!("w{window}");
    for line in booklet.lines() {
        let mut it = line.split_whitespace();
        let (Some(_date), Some(w)) = (it.next(), it.next()) else { continue };
        if w == tag {
            let words: Vec<&str> = it.collect();
            if words.len() == WORDS_PER_LINE {
                return Some(words.join(" "));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_header_tolerance() {
        let words = vec!["abandon"; WORDS_PER_LINE].join(" ");
        let booklet = format!(
            "SplitKey keyholder booklet\ncommunity: x epoch: 1\n\n{}\n{}\n",
            format_line(20_643, 86_400, &words),
            format_line(20_644, 86_400, &words),
        );
        assert_eq!(find_line(&booklet, 20_643).unwrap(), words);
        assert_eq!(find_line(&booklet, 20_644).unwrap(), words);
        assert_eq!(find_line(&booklet, 20_645), None);
    }
}
