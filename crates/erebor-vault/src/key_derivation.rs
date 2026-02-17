use erebor_common::{EreborError, Result};
use hmac::{Hmac, Mac};
use k256::{
    ecdsa::SigningKey,
    elliptic_curve::sec1::ToEncodedPoint,
    SecretKey,
};
use sha2::Sha512;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const HARDENED_OFFSET: u32 = 0x80000000;

/// Extended private key (BIP-32)
#[derive(Clone)]
pub struct ExtendedPrivateKey {
    pub secret_key: Vec<u8>, // 32 bytes
    pub chain_code: Vec<u8>, // 32 bytes
}

impl Drop for ExtendedPrivateKey {
    fn drop(&mut self) {
        self.secret_key.zeroize();
        self.chain_code.zeroize();
    }
}

/// Generate BIP-32 master key from seed
pub fn master_key_from_seed(seed: &[u8]) -> Result<ExtendedPrivateKey> {
    if seed.len() < 16 || seed.len() > 64 {
        return Err(EreborError::VaultError("Seed must be 16-64 bytes".into()));
    }
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| EreborError::VaultError(format!("HMAC init: {e}")))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let secret_key = result[..32].to_vec();
    let chain_code = result[32..].to_vec();

    // Validate the key is valid for secp256k1
    SecretKey::from_bytes(secret_key.as_slice().into())
        .map_err(|_| EreborError::VaultError("Invalid master key (zero or >= curve order)".into()))?;

    Ok(ExtendedPrivateKey { secret_key, chain_code })
}

/// Derive a child key (BIP-32)
pub fn derive_child(parent: &ExtendedPrivateKey, index: u32) -> Result<ExtendedPrivateKey> {
    let mut mac = HmacSha512::new_from_slice(&parent.chain_code)
        .map_err(|e| EreborError::VaultError(format!("HMAC init: {e}")))?;

    if index >= HARDENED_OFFSET {
        // Hardened: 0x00 || parent_key || index
        mac.update(&[0x00]);
        mac.update(&parent.secret_key);
    } else {
        // Normal: parent_pubkey || index
        let sk = SecretKey::from_bytes(parent.secret_key.as_slice().into())
            .map_err(|e| EreborError::VaultError(format!("Invalid key: {e}")))?;
        let pk = sk.public_key();
        let pk_bytes = pk.to_encoded_point(true);
        mac.update(pk_bytes.as_bytes());
    }
    mac.update(&index.to_be_bytes());

    let result = mac.finalize().into_bytes();
    let il = &result[..32];
    let ir = &result[32..];

    // child_key = (il + parent_key) mod n
    let parent_scalar = k256::NonZeroScalar::try_from(parent.secret_key.as_slice())
        .map_err(|_| EreborError::VaultError("Invalid parent key".into()))?;
    let il_scalar = k256::NonZeroScalar::try_from(il)
        .map_err(|_| EreborError::VaultError("Derived key is invalid".into()))?;

    let child_scalar = parent_scalar.as_ref() + il_scalar.as_ref();
    let child_bytes: [u8; 32] = child_scalar.to_bytes().into();

    Ok(ExtendedPrivateKey {
        secret_key: child_bytes.to_vec(),
        chain_code: ir.to_vec(),
    })
}

/// Derive key at a BIP-44 path given as array of indices (already with hardened flags)
pub fn derive_path(seed: &[u8], path: &[u32]) -> Result<ExtendedPrivateKey> {
    let mut key = master_key_from_seed(seed)?;
    for &index in path {
        key = derive_child(&key, index)?;
    }
    Ok(key)
}

/// BIP-44 Ethereum path: m/44'/60'/0'/0/index
pub fn derive_ethereum_key(seed: &[u8], index: u32) -> Result<ExtendedPrivateKey> {
    derive_path(seed, &[
        44 + HARDENED_OFFSET,
        60 + HARDENED_OFFSET,
        HARDENED_OFFSET, // account 0'
        0,               // external chain
        index,
    ])
}

/// BIP-44 Solana path: m/44'/501'/0'/0'
/// Solana uses hardened derivation for all levels
pub fn derive_solana_key(seed: &[u8]) -> Result<ExtendedPrivateKey> {
    derive_path(seed, &[
        44 + HARDENED_OFFSET,
        501 + HARDENED_OFFSET,
        HARDENED_OFFSET,
        HARDENED_OFFSET,
    ])
}

/// Get secp256k1 public key (compressed, 33 bytes)
pub fn public_key_from_private(private_key: &[u8]) -> Result<Vec<u8>> {
    let sk = SecretKey::from_bytes(private_key.into())
        .map_err(|e| EreborError::VaultError(format!("Invalid private key: {e}")))?;
    let pk = sk.public_key();
    Ok(pk.to_encoded_point(true).as_bytes().to_vec())
}

/// Get uncompressed secp256k1 public key (65 bytes, 04 || x || y)
pub fn public_key_uncompressed(private_key: &[u8]) -> Result<Vec<u8>> {
    let sk = SecretKey::from_bytes(private_key.into())
        .map_err(|e| EreborError::VaultError(format!("Invalid private key: {e}")))?;
    let pk = sk.public_key();
    Ok(pk.to_encoded_point(false).as_bytes().to_vec())
}

/// Derive Ethereum address from private key (0x-prefixed hex)
pub fn ethereum_address(private_key: &[u8]) -> Result<String> {
    let uncompressed = public_key_uncompressed(private_key)?;
    // Keccak256 of public key bytes (without 0x04 prefix)
    let mut hasher = Keccak::v256();
    hasher.update(&uncompressed[1..]); // skip 0x04
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    // Last 20 bytes
    let addr = &hash[12..];
    Ok(format!("0x{}", hex::encode(addr)))
}

/// Derive Ed25519 keypair for Solana from seed
pub fn solana_keypair_from_seed(seed: &[u8]) -> Result<ed25519_dalek::SigningKey> {
    let derived = derive_solana_key(seed)?;
    // Use first 32 bytes as Ed25519 seed
    let seed_bytes: [u8; 32] = derived.secret_key[..32].try_into()
        .map_err(|_| EreborError::VaultError("Invalid key length".into()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&seed_bytes))
}

/// Sign a 32-byte hash with secp256k1 private key (returns 64-byte signature)
pub fn secp256k1_sign(private_key: &[u8], msg_hash: &[u8; 32]) -> Result<Vec<u8>> {
    use k256::ecdsa::{signature::Signer, Signature};
    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| EreborError::VaultError(format!("Invalid signing key: {e}")))?;
    let sig: Signature = signing_key.sign(msg_hash);
    Ok(sig.to_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-32 test vector 1 from https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    #[test]
    fn test_bip32_vector1_master() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(&master.secret_key),
            "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
        );
        assert_eq!(
            hex::encode(&master.chain_code),
            "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
        );
    }

    #[test]
    fn test_bip32_vector1_child_hardened() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        // m/0'
        let child = derive_child(&master, HARDENED_OFFSET).unwrap();
        assert_eq!(
            hex::encode(&child.secret_key),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
        assert_eq!(
            hex::encode(&child.chain_code),
            "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141"
        );
    }

    #[test]
    fn test_bip32_vector2_master() {
        let seed = hex::decode(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        assert_eq!(
            hex::encode(&master.secret_key),
            "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e"
        );
    }

    #[test]
    fn test_bip32_vector1_chain_m_0h_1() {
        // m/0'/1
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let master = master_key_from_seed(&seed).unwrap();
        let child0h = derive_child(&master, HARDENED_OFFSET).unwrap();
        let child1 = derive_child(&child0h, 1).unwrap();
        assert_eq!(
            hex::encode(&child1.secret_key),
            "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368"
        );
    }

    #[test]
    fn test_ethereum_address_derivation() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();
        let key = derive_ethereum_key(&seed, 0).unwrap();
        let addr = ethereum_address(&key.secret_key).unwrap();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_ethereum_address_known() {
        // Known test: private key of all 1s
        let pk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let addr = ethereum_address(&pk).unwrap();
        assert_eq!(addr.to_lowercase(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn test_public_key_compressed() {
        let pk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let pubkey = public_key_from_private(&pk).unwrap();
        assert_eq!(pubkey.len(), 33);
        assert!(pubkey[0] == 0x02 || pubkey[0] == 0x03);
    }

    #[test]
    fn test_derive_path_roundtrip() {
        let seed = vec![0xab; 32];
        let key = derive_ethereum_key(&seed, 0).unwrap();
        assert_eq!(key.secret_key.len(), 32);
        assert_eq!(key.chain_code.len(), 32);
    }

    #[test]
    fn test_solana_keypair() {
        let seed = vec![0xcd; 64];
        let kp = solana_keypair_from_seed(&seed).unwrap();
        let vk = kp.verifying_key();
        assert_eq!(vk.as_bytes().len(), 32);
    }

    #[test]
    fn test_secp256k1_sign() {
        let pk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let msg = [0xab_u8; 32];
        let sig = secp256k1_sign(&pk, &msg).unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn test_invalid_seed_too_short() {
        assert!(master_key_from_seed(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let seed = vec![0x42; 32];
        let k0 = derive_ethereum_key(&seed, 0).unwrap();
        let k1 = derive_ethereum_key(&seed, 1).unwrap();
        assert_ne!(k0.secret_key, k1.secret_key);
    }
}
