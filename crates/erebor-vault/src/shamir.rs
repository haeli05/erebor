use erebor_common::{EreborError, Result, SecretBytes};
use rand::RngCore;
use zeroize::Zeroize;

/// Share from Shamir Secret Sharing
#[derive(Debug, Clone)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

/// Shamir Secret Sharing vault — 2-of-3 key splitting
pub struct ShamirVault {
    pub threshold: usize,
    pub total_shares: usize,
}

impl ShamirVault {
    pub fn new(threshold: usize, total_shares: usize) -> Result<Self> {
        if threshold < 2 {
            return Err(EreborError::VaultError("Threshold must be >= 2".into()));
        }
        if total_shares < threshold {
            return Err(EreborError::VaultError("Total shares must be >= threshold".into()));
        }
        if total_shares > 255 {
            return Err(EreborError::VaultError("Max 255 shares".into()));
        }
        Ok(Self { threshold, total_shares })
    }

    /// Split a secret into N shares with threshold T
    /// Uses GF(2^8) polynomial evaluation
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Share>> {
        if secret.is_empty() {
            return Err(EreborError::VaultError("Empty secret".into()));
        }

        let mut rng = rand::thread_rng();
        let mut shares: Vec<Share> = (0..self.total_shares)
            .map(|i| Share {
                index: (i + 1) as u8,
                data: vec![0u8; secret.len()],
            })
            .collect();

        // For each byte of the secret, create a polynomial and evaluate at each share index
        for (byte_idx, &secret_byte) in secret.iter().enumerate() {
            // Random coefficients for polynomial (degree = threshold - 1)
            let mut coeffs = vec![0u8; self.threshold];
            coeffs[0] = secret_byte; // constant term = secret byte
            for c in coeffs.iter_mut().skip(1) {
                let mut b = [0u8; 1];
                rng.fill_bytes(&mut b);
                *c = b[0];
            }

            // Evaluate polynomial at each share index (in GF(256))
            for share in shares.iter_mut() {
                share.data[byte_idx] = gf256_eval(&coeffs, share.index);
            }

            coeffs.zeroize();
        }

        Ok(shares)
    }

    /// Reconstruct the secret from threshold shares using Lagrange interpolation in GF(256)
    pub fn reconstruct(&self, shares: &[Share]) -> Result<SecretBytes> {
        if shares.len() < self.threshold {
            return Err(EreborError::ShareError(format!(
                "Need {} shares, got {}",
                self.threshold,
                shares.len()
            )));
        }

        let shares = &shares[..self.threshold]; // use exactly threshold shares
        let len = shares[0].data.len();

        // Verify all shares have same length
        if shares.iter().any(|s| s.data.len() != len) {
            return Err(EreborError::ShareError("Share length mismatch".into()));
        }

        let mut secret = vec![0u8; len];

        for (byte_idx, secret_byte) in secret.iter_mut().enumerate().take(len) {
            let points: Vec<(u8, u8)> = shares
                .iter()
                .map(|s| (s.index, s.data[byte_idx]))
                .collect();
            *secret_byte = gf256_interpolate(&points);
        }

        Ok(SecretBytes(secret))
    }
}

// GF(2^8) arithmetic using AES irreducible polynomial x^8 + x^4 + x^3 + x + 1

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b; // AES polynomial
        }
        b >>= 1;
    }
    result
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 {
        return 0; // no inverse for 0
    }
    // Fermat's little theorem: a^(254) = a^(-1) in GF(256)
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    result = gf256_mul(result, result);
    result
}

fn gf256_eval(coeffs: &[u8], x: u8) -> u8 {
    // Horner's method
    let mut result = 0u8;
    for &c in coeffs.iter().rev() {
        result = gf256_mul(result, x) ^ c;
    }
    result
}

fn gf256_interpolate(points: &[(u8, u8)]) -> u8 {
    let mut result = 0u8;
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut basis = yi;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                // basis *= xj / (xj ^ xi)
                let num = xj;
                let den = xj ^ xi;
                basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
            }
        }
        result ^= basis;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gf256_mul_identity() {
        assert_eq!(gf256_mul(1, 42), 42);
        assert_eq!(gf256_mul(42, 1), 42);
    }

    #[test]
    fn test_gf256_mul_zero() {
        assert_eq!(gf256_mul(0, 42), 0);
        assert_eq!(gf256_mul(42, 0), 0);
    }

    #[test]
    fn test_gf256_inverse() {
        for a in 1u16..=255 {
            let a = a as u8;
            let inv = gf256_inv(a);
            assert_eq!(gf256_mul(a, inv), 1, "a={a}, inv={inv}");
        }
    }

    #[test]
    fn test_split_reconstruct_2_of_3() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let secret = b"this is a 32-byte private key!!";
        let shares = vault.split(secret).unwrap();
        assert_eq!(shares.len(), 3);

        // Any 2 shares should reconstruct
        let recovered = vault.reconstruct(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(&recovered.0, secret);

        let recovered = vault.reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(&recovered.0, secret);

        let recovered = vault.reconstruct(&[shares[1].clone(), shares[2].clone()]).unwrap();
        assert_eq!(&recovered.0, secret);
    }

    #[test]
    fn test_split_reconstruct_3_of_5() {
        let vault = ShamirVault::new(3, 5).unwrap();
        let secret = b"another secret key material here";
        let shares = vault.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = vault.reconstruct(&[shares[0].clone(), shares[2].clone(), shares[4].clone()]).unwrap();
        assert_eq!(&recovered.0, secret);
    }

    #[test]
    fn test_single_share_insufficient() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let secret = b"secret";
        let shares = vault.split(secret).unwrap();
        let result = vault.reconstruct(&[shares[0].clone()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_threshold() {
        assert!(ShamirVault::new(1, 3).is_err());
        assert!(ShamirVault::new(5, 3).is_err());
    }

    #[test]
    fn test_empty_secret() {
        let vault = ShamirVault::new(2, 3).unwrap();
        assert!(vault.split(b"").is_err());
    }

    #[test]
    fn test_different_splits_produce_different_shares() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let secret = b"determinism check";
        let shares1 = vault.split(secret).unwrap();
        let shares2 = vault.split(secret).unwrap();
        // Random coefficients mean shares differ (with overwhelming probability)
        assert_ne!(shares1[0].data, shares2[0].data);
    }

    #[test]
    fn test_32_byte_key() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let secret = [0xAB_u8; 32]; // typical private key size
        let shares = vault.split(&secret).unwrap();
        let recovered = vault.reconstruct(&[shares[0].clone(), shares[2].clone()]).unwrap();
        assert_eq!(recovered.0, secret);
    }
}
