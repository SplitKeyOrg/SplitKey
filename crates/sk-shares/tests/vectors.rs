//! Published test vectors (README.md): fixed inputs → exact word lines.
//! An independent implementation of the spec must reproduce these.
//!
//! Shares here are *fixed values*, not outputs of `split` (which is
//! randomized) — the vectors pin the encoding + checksum, and `combine`,
//! which are the deterministic parts of the spec.

use sk_shares::{combine, decode_words, encode_words, LineCtx, Share};

const CTX: LineCtx<'static> = LineCtx { community_id: "splitkey-test", epoch: 1, window: 20_643 };

#[test]
fn vector_encode_decode() {
    let share = Share {
        x: 2,
        y: [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ],
    };
    let line = encode_words(&share, &CTX);
    // Pinned: regenerating this constant means the FORMAT changed —
    // bump a version somewhere and say so in the README.
    let expected = "acoustic above embrace grief earn rebel taste basket primary taxi \
                    danger target valve jealous";
    assert_eq!(line, expected, "encoding or checksum definition drifted");
    assert_eq!(decode_words(expected, &CTX).unwrap(), share);
}

#[test]
fn vector_combine() {
    // 2-of-n shares of the secret 000102…0e0f with polynomial f(x) = s ⊕ 1·x
    // per byte (coefficient 1 for every byte): y = s[i] ^ x.
    let secret: [u8; 16] = core::array::from_fn(|i| i as u8);
    let s1 = Share { x: 1, y: core::array::from_fn(|i| secret[i] ^ 1) };
    let s3 = Share { x: 3, y: core::array::from_fn(|i| secret[i] ^ 3) };
    assert_eq!(combine(&[s1, s3]).unwrap(), secret);
}
