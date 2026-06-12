//! SplitKey share handling: byte-wise Shamir over GF(2⁸) + the 14-word
//! booklet-line encoding. Format spec: `README.md` in this crate.
//!
//! Consumed by `Ceremony/` (split) and `Keyholders/` (combine).
//! **Never by `Sealer/`** — the camera holds only public keys.

mod gf256;
pub mod booklet;
pub mod dates;
pub mod words;

use std::collections::HashSet;

pub const SECRET_LEN: usize = 16;
pub const WORDS_PER_LINE: usize = 14;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShareError {
    #[error("need 1..=255 keyholders and 1 <= t <= n (got t={t}, n={n})")]
    BadThreshold { t: u8, n: u8 },
    #[error("combine needs at least one share")]
    NoShares,
    #[error("duplicate share x-coordinate {0} (same keyholder twice?)")]
    DuplicateX(u8),
    #[error("expected {expected} words, got {got}")]
    WrongWordCount { expected: usize, got: usize },
    #[error("word {position} ('{word}') is not in the wordlist")]
    UnknownWord { position: usize, word: String },
    #[error("padding bits nonzero — words out of order or corrupted")]
    BadPadding,
    #[error("checksum mismatch — typo, or the line is for a different window/community")]
    BadChecksum,
    #[error("share x-coordinate 0 is invalid")]
    ZeroX,
    #[error("invalid date '{0}' (expected YYYY-MM-DD, UTC)")]
    BadDate(String),
}

/// One keyholder's share of one window secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// Polynomial x-coordinate, `1..=n`. Fixed per keyholder for the whole
    /// booklet (printed in its header).
    pub x: u8,
    pub y: [u8; SECRET_LEN],
}

/// What a booklet line is bound to. All fields come from the manifest.
#[derive(Debug, Clone, Copy)]
pub struct LineCtx<'a> {
    pub community_id: &'a str,
    pub epoch: u16,
    pub window: u64,
}

/// Split `secret` into `n` shares, any `t` of which reconstruct it.
/// Byte-wise: 16 independent degree-`t-1` polynomials with random
/// coefficients (libsodium CSPRNG), secret byte as constant term.
pub fn split(secret: &[u8; SECRET_LEN], t: u8, n: u8) -> Result<Vec<Share>, ShareError> {
    if t == 0 || n == 0 || t > n {
        return Err(ShareError::BadThreshold { t, n });
    }
    let mut shares: Vec<Share> = (1..=n).map(|x| Share { x, y: [0; SECRET_LEN] }).collect();
    let mut coeffs = vec![0u8; t as usize];
    for (i, &sbyte) in secret.iter().enumerate() {
        coeffs[0] = sbyte;
        if t > 1 {
            sealer_crypto::random_bytes(&mut coeffs[1..]);
            // Degree exactly t-1, so any t-1 shares stay information-free.
            while coeffs[t as usize - 1] == 0 {
                sealer_crypto::random_bytes(&mut coeffs[t as usize - 1..t as usize]);
            }
        }
        for s in &mut shares {
            s.y[i] = gf256::poly_eval(&coeffs, s.x);
        }
    }
    Ok(shares)
}

/// Lagrange interpolation at x = 0. Any `t` *valid* shares give the secret;
/// fewer (or corrupted) shares give indistinguishable garbage — which is why
/// callers must verify the derived public key against the manifest.
pub fn combine(shares: &[Share]) -> Result<[u8; SECRET_LEN], ShareError> {
    if shares.is_empty() {
        return Err(ShareError::NoShares);
    }
    let mut seen = HashSet::new();
    for s in shares {
        if s.x == 0 {
            return Err(ShareError::ZeroX);
        }
        if !seen.insert(s.x) {
            return Err(ShareError::DuplicateX(s.x));
        }
    }
    let mut secret = [0u8; SECRET_LEN];
    for (i, out) in secret.iter_mut().enumerate() {
        let mut acc = 0u8;
        for j in shares {
            let mut basis = 1u8; // Π_{m≠j} x_m / (x_m ⊕ x_j)
            for m in shares {
                if m.x != j.x {
                    basis = gf256::mul(basis, gf256::div(m.x, m.x ^ j.x));
                }
            }
            acc ^= gf256::mul(j.y[i], basis);
        }
        *out = acc;
    }
    Ok(secret)
}

/// 2-byte checksum binding a share line to community + epoch + window.
fn line_check(share: &Share, ctx: &LineCtx) -> [u8; 2] {
    let id = ctx.community_id.as_bytes();
    let mut buf = Vec::with_capacity(2 + id.len() + 2 + 8 + 1 + SECRET_LEN);
    buf.extend_from_slice(&(id.len() as u16).to_be_bytes());
    buf.extend_from_slice(id);
    buf.extend_from_slice(&ctx.epoch.to_be_bytes());
    buf.extend_from_slice(&ctx.window.to_be_bytes());
    buf.push(share.x);
    buf.extend_from_slice(&share.y);
    let h = sealer_crypto::blake2b256(&buf);
    [h[0], h[1]]
}

/// Share → one booklet line: 14 lowercase words, space-separated.
pub fn encode_words(share: &Share, ctx: &LineCtx) -> String {
    let mut payload = [0u8; 19];
    payload[0] = share.x;
    payload[1..17].copy_from_slice(&share.y);
    payload[17..19].copy_from_slice(&line_check(share, ctx));
    words::bytes_to_words(&payload).join(" ")
}

/// One booklet line → share, verifying the checksum against `ctx`.
/// Whitespace-tolerant and case-insensitive.
pub fn decode_words(line: &str, ctx: &LineCtx) -> Result<Share, ShareError> {
    let payload = words::words_to_bytes(line)?;
    let share = Share { x: payload[0], y: payload[1..17].try_into().unwrap() };
    if share.x == 0 {
        return Err(ShareError::ZeroX);
    }
    if payload[17..19] != line_check(&share, ctx) {
        return Err(ShareError::BadChecksum);
    }
    Ok(share)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> LineCtx<'static> {
        LineCtx { community_id: "maple-street", epoch: 1, window: 20_643 }
    }

    #[test]
    fn split_combine_roundtrip_all_quorums() {
        let secret: [u8; 16] = sealer_crypto::random_32()[..16].try_into().unwrap();
        let shares = split(&secret, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);
        // every 3-of-5 subset reconstructs
        for a in 0..5 {
            for b in a + 1..5 {
                for c in b + 1..5 {
                    let got = combine(&[shares[a].clone(), shares[b].clone(), shares[c].clone()])
                        .unwrap();
                    assert_eq!(got, secret);
                }
            }
        }
        // 2 shares give garbage (overwhelmingly), never an error
        let two = combine(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_ne!(two, secret);
    }

    #[test]
    fn one_of_one_and_n_of_n() {
        let secret = [9u8; 16];
        let s = split(&secret, 1, 1).unwrap();
        assert_eq!(combine(&s).unwrap(), secret);
        let s = split(&secret, 5, 5).unwrap();
        assert_eq!(combine(&s).unwrap(), secret);
        assert_ne!(combine(&s[..4]).unwrap(), secret);
    }

    #[test]
    fn combine_input_validation() {
        assert_eq!(combine(&[]).unwrap_err(), ShareError::NoShares);
        let s = Share { x: 1, y: [0; 16] };
        assert_eq!(
            combine(&[s.clone(), s]).unwrap_err(),
            ShareError::DuplicateX(1)
        );
        assert!(matches!(split(&[0; 16], 4, 3), Err(ShareError::BadThreshold { .. })));
    }

    #[test]
    fn words_roundtrip_and_checksum_binding() {
        let secret = [0xAB; 16];
        let shares = split(&secret, 2, 3).unwrap();
        let line = encode_words(&shares[1], &ctx());
        assert_eq!(line.split_whitespace().count(), WORDS_PER_LINE);

        let back = decode_words(&line, &ctx()).unwrap();
        assert_eq!(back, shares[1]);

        // tolerant input
        let messy = format!("  {}  ", line.to_uppercase().replace(' ', "   "));
        assert_eq!(decode_words(&messy, &ctx()).unwrap(), shares[1]);

        // wrong window / epoch / community all fail the checksum
        for bad in [
            LineCtx { window: 20_644, ..ctx() },
            LineCtx { epoch: 2, ..ctx() },
            LineCtx { community_id: "other-street", ..ctx() },
        ] {
            assert_eq!(decode_words(&line, &bad).unwrap_err(), ShareError::BadChecksum);
        }

        // a typo'd word fails the checksum (or the wordlist lookup)
        let mut w: Vec<&str> = line.split_whitespace().collect();
        w[3] = if w[3] == "zoo" { "zebra" } else { "zoo" };
        let typo = w.join(" ");
        assert!(decode_words(&typo, &ctx()).is_err());
    }
}
