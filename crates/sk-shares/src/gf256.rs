//! GF(2⁸) arithmetic over the AES polynomial `0x11B`, via log/exp tables
//! (generator 3). The field SLIP-39 and `sharks` use for byte-wise Shamir.

const fn build_tables() -> ([u8; 256], [u8; 256]) {
    let mut exp = [0u8; 256];
    let mut log = [0u8; 256];
    let mut x: u8 = 1;
    let mut i = 0usize;
    while i < 255 {
        exp[i] = x;
        log[x as usize] = i as u8;
        // x *= 3  (3 = generator):  x ^ xtime(x)
        let mut xt = x << 1;
        if x & 0x80 != 0 {
            xt ^= 0x1B;
        }
        x ^= xt;
        i += 1;
    }
    exp[255] = exp[0]; // never indexed in mul (mod 255), kept total
    (exp, log)
}

const TABLES: ([u8; 256], [u8; 256]) = build_tables();
const EXP: [u8; 256] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    EXP[(LOG[a as usize] as usize + LOG[b as usize] as usize) % 255]
}

/// a / b. Panics on b == 0 (never reachable: divisors are `x_m ⊕ x_j` of
/// distinct nonzero x-coordinates).
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(256)");
    if a == 0 {
        return 0;
    }
    EXP[(LOG[a as usize] as usize + 255 - LOG[b as usize] as usize) % 255]
}

/// Evaluate `coeffs[0] + coeffs[1]·x + …` (Horner, constant term = secret).
pub fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_axioms_spot_checks() {
        // distributivity + inverses over the whole field
        for a in 1..=255u8 {
            assert_eq!(mul(a, div(1, a)), 1, "inverse of {a}");
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
        }
        // known product in AES field: 0x57 * 0x83 = 0xC1
        assert_eq!(mul(0x57, 0x83), 0xC1);
    }

    #[test]
    fn horner_matches_naive() {
        let coeffs = [7u8, 0, 255, 19];
        let x = 0x53;
        let naive = coeffs
            .iter()
            .enumerate()
            .fold(0u8, |acc, (i, &c)| {
                let mut xi = 1u8;
                for _ in 0..i {
                    xi = mul(xi, x);
                }
                acc ^ mul(c, xi)
            });
        assert_eq!(poly_eval(&coeffs, x), naive);
    }
}
