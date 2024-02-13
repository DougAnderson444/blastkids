#![doc = include_str!("../README.md")]
pub mod kdf;

// re-exports
pub use bls12_381_plus::elliptic_curve::ops::MulByGenerator;
pub use bls12_381_plus::group::{Group, GroupEncoding};
pub use bls12_381_plus::G1Projective as G1;
pub use bls12_381_plus::G2Projective as G2;
pub use bls12_381_plus::Scalar;
pub use secrecy::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use secrecy::{ExposeSecret, Secret};

use thiserror::Error;

// Test the README.md code snippets
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// Seed and master key Manager.
///
/// Generic over the type of curve used, [either G1 or G2](https://hackmd.io/@benjaminion/bls12-381#Swapping-G1-and-G2)
///
/// ```rust
/// use blastkids::{Manager, Zeroizing};
/// use bls12_381_plus::G1Projective as G1;
/// use bls12_381_plus::G2Projective as G2;
/// // use blastkids::{G1, G2}; <== re-exported for convenience
///
/// // a G1 public key
/// let seed = Zeroizing::new([69u8; 32]);
/// let manager: Manager<G1> = Manager::from_seed(seed);
///
/// // or if you like, make a new manager for a G2 public key
/// let seed = Zeroizing::new([42u8; 32]);
/// let manager: Manager<G2> = Manager::from_seed(seed);
/// ```
///
pub struct Manager<T: GroupEncoding> {
    master_sk: Scalar,
    pub master_pk: T,
}

impl<T: GroupEncoding + MulByGenerator + Group<Scalar = Scalar>> Manager<T> {
    /// Create a new Manager from a master secret key
    /// and derive the master public key from it.
    fn new(master_sk: Scalar) -> Self {
        let master_pk: T = T::mul_by_generator(&master_sk);
        Self {
            master_sk,
            master_pk,
        }
    }

    /// Create a new Manager from a seed.
    ///
    /// The seed is used to derive the master secret key. The seed passed
    /// must covert to bytes and [Zeroize] and [ZeroizeOnDrop] for your memory safety.
    pub fn from_seed(seed: impl AsRef<[u8]> + Zeroize + ZeroizeOnDrop) -> Self {
        let master_sk: Scalar =
            kdf::derive_master_sk(seed.as_ref()).expect("Seed has length of 32 bytes");
        Self::new(master_sk)
    }

    /// Returns the Account at the index.
    ///
    /// Uses the master secret key to create a hardened account key,
    /// then [Account] uses this hardened account key to create a derived
    /// non-hardened sub-account (child) keys.
    ///
    /// This way the user can create new accounts for the same seed
    /// and also rotate them in the event of compromise without
    /// compromising the master secret key.
    pub fn account(&self, index: u32) -> Account<T> {
        // first derive a hardened key for the account
        let derived_sk: Scalar = kdf::ckd_sk_hardened(&self.master_sk, index);
        // since the account public key is hardened and cannot expose the master seed/secret
        let derived_pk = T::mul_by_generator(&derived_sk);

        Account {
            index,
            sk: Secret::new(derived_sk),
            pk: derived_pk,
        }
    }
}

/// An Account is a hardened key derived from the master secret key.
///
/// It is generic over the type of curve used, either G1 or G2.
pub struct Account<T: GroupEncoding + MulByGenerator + Group<Scalar = Scalar>> {
    pub index: u32,
    sk: Secret<Scalar>,
    pub pk: T,
}

impl<T: GroupEncoding + MulByGenerator + Group<Scalar = Scalar>> Account<T> {
    /// Create a new account from a secret key and public key
    pub fn new(index: u32, sk: Scalar, pk: T) -> Self {
        Self {
            index,
            sk: Secret::new(sk),
            pk,
        }
    }

    /// Expand an Account given a length, using the Account's secret key to derive the additional keys.
    ///
    /// Function is deterministic, and always exapands to the same keys at each index.
    ///
    /// Maximum length is 255 as there is no practical use case for keys longer than this (yet)
    pub fn expand_to(&self, length: u8) -> Expanded<T> {
        let sk = Secret::new(
            (0..length)
                .map(|i| kdf::ckd_sk_normal::<T>(self.sk.expose_secret(), i as u32))
                .collect::<Vec<Scalar>>(),
        );

        // Iterate over the secret keys and derive the corresponding public keys
        let pk = derive(&self.pk, length);
        Expanded { sk, pk }
    }
}

/// When an Account uses a length to derive a Child Account,
/// this struct is returned. It contains both Public Key and Secret Key
/// in vectors.
pub struct Expanded<T: GroupEncoding + MulByGenerator + Group<Scalar = Scalar>> {
    pub sk: Secret<Vec<Scalar>>,
    pub pk: Vec<T>,
}

/// Given an Account root Public Key and a length,
/// derive the child account public keys
pub fn derive<T: GroupEncoding + Group<Scalar = Scalar> + MulByGenerator>(
    pk: &T,
    length: u8,
) -> Vec<T> {
    (0..length)
        .map(|i| kdf::ckd_pk_normal::<T>(pk, i as u32))
        .collect::<Vec<T>>()
}

#[cfg(test)]
mod basic_test {

    use secrecy::zeroize::Zeroizing;

    use super::*;

    #[test]
    fn smoke() {
        let seed = Zeroizing::new([69u8; 32]);
        let manager: Manager<G2> = Manager::from_seed(seed);
        let pk2 = G2::mul_by_generator(&manager.master_sk);
        assert_eq!(manager.master_pk, pk2);

        println!(
            "master_pk [{}]: compressed: [{:?}]",
            // print master_pk as GroupEncoding to use serialize_uncompressed
            manager.master_pk.to_bytes().as_ref().len(),
            manager.master_pk.to_bytes().as_ref().len()
        );

        println!("master_sk [{}]", manager.master_sk);

        let purpose = 1u32; // is not part of the m / path index.
        let length = 8u8;
        // a user derived account #2 matches the issuer derived account #2
        let account = manager.account(purpose);
        // derived second floor from floor_account_pk
        let child = account.expand_to(length);

        // should match the issuer derived account #2 from secret keys
        let hardened_child_sk = kdf::ckd_sk_hardened(&manager.master_sk, purpose);

        // account sk should match hardened_child_sk
        assert_eq!(account.sk.expose_secret(), &hardened_child_sk);

        // should be the same length, matching length above
        assert_eq!(child.sk.expose_secret().len(), length as usize);
        assert_eq!(child.pk.len(), length as usize);

        // Given an Account and a `length`, we can derive a child account
        let child_account = derive(&account.pk, length);

        // iterate over the secret keys and derive the corresponding public keys
        // check to ensure the index values match
        for (i, sk) in child.sk.expose_secret().iter().enumerate() {
            let normal_pk = G2::mul_by_generator(sk);
            assert_eq!(normal_pk, child.pk[i]);
            // also should match child_account[i]
            assert_eq!(normal_pk, child_account[i]);
        }

        // should match the issuer derived account #2 from public keys
    }
}
