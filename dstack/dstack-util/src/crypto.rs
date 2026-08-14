// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::{
    aead::{Aead, Nonce},
    Aes256Gcm, KeyInit,
};
use anyhow::{anyhow, Result};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn dh_agree(secret: [u8; 32], their_pubkey: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(secret);
    let their_public = PublicKey::from(their_pubkey);
    let shared_secret = secret.diffie_hellman(&their_public);
    shared_secret.to_bytes()
}

pub fn dh_decrypt(secret: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Extract components (matching JS implementation)
    let ephemeral_pubkey = ciphertext
        .get(..32)
        .ok_or(anyhow!("Invalid ephemeral public key length"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid ephemeral public key length"))?;
    let iv = &ciphertext.get(32..44).ok_or(anyhow!("Invalid IV length"))?;
    let ciphertext = &ciphertext
        .get(44..)
        .ok_or(anyhow!("Invalid ciphertext length"))?;

    // Derive shared secret using X25519
    let shared_secret = dh_agree(secret, ephemeral_pubkey);
    if shared_secret.iter().all(|byte| *byte == 0) {
        return Err(anyhow!("invalid X25519 shared secret"));
    }

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    // Decrypt using AES-GCM
    cipher
        .decrypt(Nonce::<Aes256Gcm>::from_slice(iv), ciphertext.as_ref())
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

/// The X25519 public key matching `secret`, i.e. the key a client would
/// encrypt to so that `dh_decrypt(secret, ..)` can open the result.
#[cfg(test)]
pub fn dh_public_key(secret: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(secret)).to_bytes()
}

/// Inverse of [`dh_decrypt`], for tests only: encrypt to `their_pubkey`,
/// producing `ephemeral_pubkey(32) || iv(12) || ciphertext+tag`. The raw
/// X25519 shared secret is the AES-256-GCM key, with no KDF, exactly as
/// `dh_decrypt` expects.
#[cfg(test)]
pub fn dh_encrypt(their_pubkey: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    use rand::RngCore as _;

    let mut rng = rand::thread_rng();
    let mut ephemeral_secret = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret);
    let ephemeral_secret = StaticSecret::from(ephemeral_secret);
    let ephemeral_pubkey = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret
        .diffie_hellman(&PublicKey::from(their_pubkey))
        .to_bytes();

    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("failed to create cipher: {}", e))?;
    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);
    let ciphertext = cipher
        .encrypt(Nonce::<Aes256Gcm>::from_slice(&iv), plaintext)
        .map_err(|e| anyhow!("encryption failed: {}", e))?;

    let mut out = Vec::with_capacity(32 + 12 + ciphertext.len());
    out.extend_from_slice(ephemeral_pubkey.as_bytes());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_agree() {
        use rand::Rng;
        let secret = rand::thread_rng().gen::<[u8; 32]>();
        let pubkey = rand::thread_rng().gen::<[u8; 32]>();
        let shared = dh_agree(secret, pubkey);
        assert_eq!(shared.len(), 32);
        println!("secret: {:?}", hex::encode(secret));
        println!("pubkey: {:?}", hex::encode(pubkey));
        println!("shared: {:?}", hex::encode(shared));
    }

    #[test]
    fn test_dh_encrypt_roundtrip() {
        let secret = [7u8; 32];
        let ciphertext = dh_encrypt(dh_public_key(secret), b"hello").unwrap();
        assert_eq!(dh_decrypt(secret, &ciphertext).unwrap(), b"hello");
        // A different recipient key must not open it.
        assert!(dh_decrypt([8u8; 32], &ciphertext).is_err());
    }

    #[test]
    fn test_dh_decrypt_invalid_input() {
        let secret = [0u8; 32];

        // Test empty input
        assert!(dh_decrypt(secret, &[]).is_err());

        // Test input too short for public key
        assert!(dh_decrypt(secret, &[0u8; 31]).is_err());

        // Test input too short for IV
        assert!(dh_decrypt(secret, &[0u8; 43]).is_err());

        // Test input with no ciphertext
        assert!(dh_decrypt(secret, &[0u8; 44]).is_err());
    }

    #[test]
    fn test_dh_decrypt() {
        let secret: [u8; 32] =
            hex::decode("7c282bf94b35dc47801dc953bfa0896fc2bd313381d3e8eca4e42f6536d2a96f")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext = hex::decode("0bd18749612f4c8b9dd583c7d6a646b90abd34e3c731a7708d0caf9039095641e1f0948e775f0b7351788db7f246d51806954626dcccb6a60d64665ca3715c6bef75616cab476d27bba04080361200d6a58cec").unwrap();
        let decrypted = dh_decrypt(secret, &ciphertext).unwrap();
        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_str, "[{\"key\":\"\",\"value\":\"\"}]");
    }
}
