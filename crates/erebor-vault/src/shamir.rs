use erebor_common::{EreborError, Result, SecretBytes};
use sharks::{Sharks, Share as SharksShare};

/// Share from Shamir Secret Sharing
#[derive(Debug, Clone)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

/// Shamir Secret Sharing vault — using sharks crate for secure implementation
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
    /// Uses the well-tested sharks library for secure Shamir secret sharing
    pub fn split(&self, secret: &[u8]) -> Result<Vec<Share>> {
        if secret.is_empty() {
            return Err(EreborError::VaultError("Empty secret".into()));
        }

        let sharks = Sharks(self.threshold as u8);
        let dealer = sharks.dealer(secret);
        let sharks_shares: Vec<SharksShare> = dealer.take(self.total_shares).collect();

        let shares = sharks_shares
            .into_iter()
            .enumerate()
            .map(|(i, sharks_share)| {
                // Convert sharks share to bytes and create our Share format
                let sharks_bytes: Vec<u8> = (&sharks_share).into();
                Share {
                    index: (i + 1) as u8,
                    data: sharks_bytes,
                }
            })
            .collect();

        Ok(shares)
    }

    /// Reconstruct the secret from threshold shares using the sharks library
    pub fn reconstruct(&self, shares: &[Share]) -> Result<SecretBytes> {
        if shares.len() < self.threshold {
            return Err(EreborError::ShareError(format!(
                "Need {} shares, got {}",
                self.threshold,
                shares.len()
            )));
        }

        let sharks = Sharks(self.threshold as u8);
        
        // Convert our Share format to sharks shares
        let sharks_shares: std::result::Result<Vec<SharksShare>, _> = shares
            .iter()
            .take(self.threshold)
            .map(|share| SharksShare::try_from(share.data.as_slice()))
            .collect();

        let sharks_shares = sharks_shares
            .map_err(|e| EreborError::ShareError(format!("Invalid share format: {e}")))?;

        let secret = sharks
            .recover(&sharks_shares)
            .map_err(|e| EreborError::ShareError(format!("Failed to reconstruct secret: {e}")))?;

        Ok(SecretBytes(secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let secret = b"another secret key for testing!";
        let shares = vault.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        // Any 3 shares should reconstruct
        let recovered = vault.reconstruct(&shares[0..3]).unwrap();
        assert_eq!(&recovered.0, secret);

        let recovered = vault.reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]).unwrap();
        assert_eq!(&recovered.0, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let secret = b"test secret";
        let shares = vault.split(secret).unwrap();

        // Only 1 share should fail
        let result = vault.reconstruct(&shares[0..1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_secret() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let result = vault.split(&[]);
        assert!(result.is_err());
    }
}