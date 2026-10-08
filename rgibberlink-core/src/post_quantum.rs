//! Post-Quantum Cryptographic primitives for RealGibber
//!
//! Implements Kyber-768 KEM and Dilithium3 digital signatures
//! for quantum-resistant key exchange and authentication.

use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::crypto::CryptoError;
use std::time::Instant;

#[cfg(feature = "post-quantum")]
use pqcrypto_kyber::kyber768;
#[cfg(feature = "post-quantum")]
use pqcrypto_dilithium::dilithium3;
#[cfg(feature = "post-quantum")]
use pqcrypto_traits::{kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _}, sign::{PublicKey as _, SecretKey as _, DetachedSignature as _}};

#[cfg(feature = "post-quantum")]
/// Kyber-768 Key Encapsulation Mechanism
pub struct KyberKEM;

#[cfg(feature = "post-quantum")]
impl KyberKEM {
    /// Generate a new Kyber-768 keypair
    pub fn generate_keypair() -> Result<KyberKeypair, CryptoError> {
        // Generate keypair using pqcrypto
        let (pk, sk) = kyber768::keypair();
        Ok(KyberKeypair {
            public_key: pk,
            secret_key: zeroize::Zeroizing::new(sk.as_bytes().to_vec()),
            created_at: Instant::now(),
        })
    }

    /// Encapsulate a shared secret using recipient's public key
    pub fn encapsulate(pk: &KyberPublicKey) -> Result<KyberCiphertextData, CryptoError> {
        let (shared_secret, ciphertext) = kyber768::encapsulate(pk);
        Ok(KyberCiphertextData {
            ciphertext,
            shared_secret: KyberSharedSecret(zeroize::Zeroizing::new(shared_secret.as_bytes().to_vec())),
        })
    }

    /// Decapsulate a shared secret using recipient's secret key
    pub fn decapsulate(sk: &KyberSecretKey, ct: &KyberCiphertext) -> Result<KyberSharedSecret, CryptoError> {
        let sk = kyber768::SecretKey::from_bytes(sk).map_err(|_| CryptoError::InvalidKeyLength)?;
        let shared_secret = kyber768::decapsulate(ct, &sk);
        Ok(KyberSharedSecret(zeroize::Zeroizing::new(shared_secret.as_bytes().to_vec())))
    }
}

#[cfg(feature = "post-quantum")]
/// Dilithium3 Digital Signature
pub struct DilithiumSign;

#[cfg(feature = "post-quantum")]
impl DilithiumSign {
    /// Generate a new Dilithium3 keypair
    pub fn generate_keypair() -> Result<DilithiumKeypair, CryptoError> {
        let (pk, sk) = dilithium3::keypair();
        Ok(DilithiumKeypair {
            public_key: pk,
            secret_key: zeroize::Zeroizing::new(sk.as_bytes().to_vec()),
            created_at: Instant::now(),
        })
    }

    /// Sign a message
    pub fn sign(sk: &DilithiumSecretKey, message: &[u8]) -> Result<DilithiumSignature, CryptoError> {
        let sk = dilithium3::SecretKey::from_bytes(sk).map_err(|_| CryptoError::InvalidKeyLength)?;
        let signature = dilithium3::detached_sign(message, &sk);
        Ok(signature)
    }

    /// Verify a signature
    pub fn verify(pk: &DilithiumPublicKey, message: &[u8], signature: &DilithiumSignature) -> Result<bool, CryptoError> {
        Ok(dilithium3::verify_detached_signature(signature, message, pk).is_ok())
    }
}

#[cfg(feature = "post-quantum")]
/// PQ Keypair structures with secure zeroization
#[derive(Clone)]
pub struct KyberKeypair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
    pub created_at: Instant,
}

#[cfg(feature = "post-quantum")]
impl Zeroize for KyberKeypair {
    fn zeroize(&mut self) {
        // Serialized long-lived secret bytes are zeroized; upstream key copies are not.
        self.secret_key.zeroize();
    }
}

#[cfg(feature = "post-quantum")]
impl Drop for KyberKeypair { fn drop(&mut self) { self.zeroize(); } }
#[cfg(feature = "post-quantum")]
impl ZeroizeOnDrop for KyberKeypair {}

#[cfg(feature = "post-quantum")]
#[derive(Clone)]
pub struct DilithiumKeypair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
    pub created_at: Instant,
}

#[cfg(feature = "post-quantum")]
impl Zeroize for DilithiumKeypair {
    fn zeroize(&mut self) {
        // Serialized long-lived secret bytes are zeroized; upstream key copies are not.
        self.secret_key.zeroize();
    }
}

#[cfg(feature = "post-quantum")]
impl Drop for DilithiumKeypair { fn drop(&mut self) { self.zeroize(); } }
#[cfg(feature = "post-quantum")]
impl ZeroizeOnDrop for DilithiumKeypair {}

#[cfg(feature = "post-quantum")]
#[derive(Clone)]
pub struct KyberCiphertextData {
    pub ciphertext: KyberCiphertext,
    pub shared_secret: KyberSharedSecret,
}

// Type aliases for PQ primitives
#[cfg(feature = "post-quantum")]
pub type KyberPublicKey = kyber768::PublicKey;
#[cfg(feature = "post-quantum")]
pub type KyberSecretKey = zeroize::Zeroizing<Vec<u8>>;
#[cfg(feature = "post-quantum")]
pub type KyberCiphertext = kyber768::Ciphertext;
#[cfg(feature = "post-quantum")]
#[derive(Clone)]
pub struct KyberSharedSecret(zeroize::Zeroizing<Vec<u8>>);
impl KyberSharedSecret {
    pub fn as_bytes(&self) -> &[u8] { self.0.as_slice() }
}

#[cfg(feature = "post-quantum")]
pub type DilithiumPublicKey = dilithium3::PublicKey;
#[cfg(feature = "post-quantum")]
pub type DilithiumSecretKey = zeroize::Zeroizing<Vec<u8>>;
#[cfg(feature = "post-quantum")]
pub type DilithiumSignature = dilithium3::DetachedSignature;

/// Post-Quantum cryptographic engine
#[cfg(feature = "post-quantum")]
pub struct PostQuantumEngine {
    kyber_keypair: KyberKeypair,
    dilithium_keypair: DilithiumKeypair,
}

#[cfg(feature = "post-quantum")]
impl PostQuantumEngine {
    /// Create a new PQ engine with fresh keypairs
    pub fn new() -> Result<Self, CryptoError> {
        let kyber_keypair = KyberKEM::generate_keypair()?;
        let dilithium_keypair = DilithiumSign::generate_keypair()?;

        Ok(Self {
            kyber_keypair,
            dilithium_keypair,
        })
    }

    /// Get Kyber public key
    pub fn kyber_public_key(&self) -> &KyberPublicKey {
        &self.kyber_keypair.public_key
    }

    /// Get Dilithium public key
    pub fn dilithium_public_key(&self) -> &DilithiumPublicKey {
        &self.dilithium_keypair.public_key
    }

    /// Perform PQ key encapsulation
    pub fn encapsulate_secret(&self, peer_pk: &KyberPublicKey) -> Result<KyberCiphertextData, CryptoError> {
        KyberKEM::encapsulate(peer_pk)
    }

    /// Perform PQ key decapsulation
    pub fn decapsulate_secret(&self, ciphertext: &KyberCiphertext) -> Result<KyberSharedSecret, CryptoError> {
        KyberKEM::decapsulate(&self.kyber_keypair.secret_key, ciphertext)
    }

    /// Sign data with Dilithium3
    pub fn sign_data(&self, data: &[u8]) -> Result<DilithiumSignature, CryptoError> {
        DilithiumSign::sign(&self.dilithium_keypair.secret_key, data)
    }

    /// Verify Dilithium3 signature
    pub fn verify_signature(&self, data: &[u8], signature: &DilithiumSignature, public_key: &DilithiumPublicKey) -> Result<bool, CryptoError> {
        DilithiumSign::verify(public_key, data, signature)
    }
}

#[cfg(not(feature = "post-quantum"))]
/// Stub implementation when PQ features are not enabled
pub struct PostQuantumEngine;

#[cfg(not(feature = "post-quantum"))]
impl PostQuantumEngine {
    pub fn new() -> Result<Self, CryptoError> {
        Err(CryptoError::GenericError("Post-quantum cryptography not enabled".to_string()))
    }
}

#[cfg(test)]
#[cfg(feature = "post-quantum")]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_kem() {
        let bob = KyberKEM::generate_keypair().unwrap();

        // Alice encapsulates for Bob
        let alice_ct = KyberKEM::encapsulate(&bob.public_key).unwrap();

        // Bob decapsulates
        let bob_ss = KyberKEM::decapsulate(&bob.secret_key, &alice_ct.ciphertext).unwrap();

        // Verify shared secrets match
        assert_eq!(alice_ct.shared_secret.as_bytes(), bob_ss.as_bytes());
    }

    #[test]
    fn test_dilithium_sign() {
        let alice = DilithiumSign::generate_keypair().unwrap();
        let message = b"Hello, quantum-resistant world!";

        // Sign message
        let signature = DilithiumSign::sign(&alice.secret_key, message).unwrap();

        // Verify signature
        let valid = DilithiumSign::verify(&alice.public_key, message, &signature).unwrap();
        assert!(valid);

        // Verify with wrong message fails
        let invalid = DilithiumSign::verify(&alice.public_key, b"Wrong message", &signature).unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_pq_engine() {
        let alice = PostQuantumEngine::new().unwrap();
        let bob = PostQuantumEngine::new().unwrap();

        // Test key exchange
        let alice_ct = alice.encapsulate_secret(bob.kyber_public_key()).unwrap();
        let bob_ss = bob.decapsulate_secret(&alice_ct.ciphertext).unwrap();

        assert_eq!(alice_ct.shared_secret.as_bytes(), bob_ss.as_bytes());

        // Test signatures
        let message = b"Authenticated quantum message";
        let signature = alice.sign_data(message).unwrap();
        let verified = bob.verify_signature(message, &signature, alice.dilithium_public_key()).unwrap();
        assert!(verified);
    }
}