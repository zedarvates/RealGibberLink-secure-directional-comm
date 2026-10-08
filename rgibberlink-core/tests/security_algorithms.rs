//! Check that narrowing pqcrypto features retains the two algorithms in use.
#![cfg(feature = "post-quantum")]

use pqcrypto_kyber::kyber768;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::kem::SharedSecret;

#[test]
fn kyber768_shared_secret_roundtrip() {
    let (public, secret) = kyber768::keypair();
    let (sender_secret, ciphertext) = kyber768::encapsulate(&public);
    let receiver_secret = kyber768::decapsulate(&ciphertext, &secret);
    assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
}

#[test]
fn dilithium3_signature_rejects_tampered_message() {
    let (public, secret) = dilithium3::keypair();
    let signature = dilithium3::detached_sign(b"security migration", &secret);
    assert!(dilithium3::verify_detached_signature(&signature, b"security migration", &public).is_ok());
    assert!(dilithium3::verify_detached_signature(&signature, b"tampered", &public).is_err());
}

#[test]
fn unsupported_hybrid_exchange_fails_closed() {
    let mut alice = gibberlink_core::crypto::CryptoEngine::new();
    let bob = gibberlink_core::crypto::CryptoEngine::new();
    assert!(alice.hybrid_key_exchange(bob.ecdh_public_key(), bob.kyber_public_key().unwrap()).is_err());
}
