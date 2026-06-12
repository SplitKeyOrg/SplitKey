//! 19-byte payload ⇄ 14 BIP39 words (11 bits each; 152 payload bits + 2
//! zero padding bits). Only the *wordlist* is BIP39 — no BIP39 checksum or
//! derivation. Every word is unique in its first 4 letters.

use crate::ShareError;
use std::collections::HashMap;
use std::sync::LazyLock;

pub const PAYLOAD_LEN: usize = 19;

static WORDLIST: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    let words: Vec<&'static str> = include_str!("../data/bip39-english.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(words.len(), 2048, "vendored wordlist corrupted");
    words
});

static INDEX: LazyLock<HashMap<&'static str, u16>> = LazyLock::new(|| {
    WORDLIST.iter().enumerate().map(|(i, &w)| (w, i as u16)).collect()
});

pub fn bytes_to_words(payload: &[u8; PAYLOAD_LEN]) -> Vec<&'static str> {
    let mut out = Vec::with_capacity(crate::WORDS_PER_LINE);
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    for &b in payload {
        bits = (bits << 8) | b as u32;
        nbits += 8;
        while nbits >= 11 {
            nbits -= 11;
            out.push(WORDLIST[((bits >> nbits) & 0x7FF) as usize]);
        }
    }
    // 152 = 13·11 + 9: pad the final 9 bits with 2 zero bits.
    debug_assert_eq!(nbits, 9);
    out.push(WORDLIST[((bits << (11 - nbits)) & 0x7FF) as usize]);
    out
}

pub fn words_to_bytes(line: &str) -> Result<[u8; PAYLOAD_LEN], ShareError> {
    let words: Vec<String> = line.split_whitespace().map(str::to_lowercase).collect();
    if words.len() != crate::WORDS_PER_LINE {
        return Err(ShareError::WrongWordCount {
            expected: crate::WORDS_PER_LINE,
            got: words.len(),
        });
    }
    let mut payload = [0u8; PAYLOAD_LEN];
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut pos = 0usize;
    for (i, w) in words.iter().enumerate() {
        let idx = *INDEX.get(w.as_str()).ok_or_else(|| ShareError::UnknownWord {
            position: i + 1,
            word: w.clone(),
        })? as u32;
        bits = (bits << 11) | idx;
        nbits += 11;
        while nbits >= 8 && pos < PAYLOAD_LEN {
            nbits -= 8;
            payload[pos] = ((bits >> nbits) & 0xFF) as u8;
            pos += 1;
        }
    }
    debug_assert_eq!(pos, PAYLOAD_LEN);
    debug_assert_eq!(nbits, 2);
    if bits & 0b11 != 0 {
        return Err(ShareError::BadPadding);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_extremes() {
        for payload in [[0u8; 19], [0xFF; 19], {
            let mut p = [0u8; 19];
            for (i, b) in p.iter_mut().enumerate() {
                *b = (i * 37) as u8;
            }
            p
        }] {
            let words = bytes_to_words(&payload);
            assert_eq!(words.len(), 14);
            let back = words_to_bytes(&words.join(" ")).unwrap();
            assert_eq!(back, payload);
        }
    }

    #[test]
    fn all_zero_payload_is_all_abandon() {
        // 0-bits everywhere → word index 0 ("abandon") × 14
        assert_eq!(bytes_to_words(&[0; 19]), vec!["abandon"; 14]);
    }

    #[test]
    fn nonzero_padding_rejected() {
        // last word index with a low bit set that falls in the padding
        let mut words = bytes_to_words(&[0; 19]);
        words[13] = WORDLIST[1]; // index 1 = "ability": low padding bit set
        assert_eq!(
            words_to_bytes(&words.join(" ")).unwrap_err(),
            ShareError::BadPadding
        );
    }
}
