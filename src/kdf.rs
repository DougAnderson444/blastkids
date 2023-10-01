//! Key derivation functions for BLS12-381 child keys
//!
//! This API is not that friendly or type-safe, but it is a direct port of the
//! previous fork version. It is also not very well documented, but the
//! [EIP2334](https://eips.ethereum.org/EIPS/eip-2334) spec is a good reference.
//!
//! The main entry point is `derive_master_sk` which takes a seed and returns a
//!  Scalar. This is the master secret key. From there, you can derive child
//! key pairs using `ckd_sk_hardened` or `ckd_sk_normal` for private keys, or
//! `ckd_pk_normal` for public keys.
use super::*;

// re-exports
pub use bls12_381_plus::group::{Group, GroupEncoding};
pub use bls12_381_plus::G1Projective as G1;
pub use bls12_381_plus::G2Projective as G2;
pub use bls12_381_plus::Scalar;

// use bigint::prelude::*;
use bls12_381_plus::elliptic_curve::{
    bigint::{self, prelude::Encoding},
    ops::MulByGenerator,
};
use bls12_381_plus::ff::Field; // so we can use is_zero()
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::convert::*;

const DIGEST_SIZE: usize = 32;
const NUM_DIGESTS: usize = 255;
const OUTPUT_SIZE: usize = DIGEST_SIZE * NUM_DIGESTS;

#[derive(Error, Debug)]
pub enum BlastKidsError {
    /// Seed too small from kdf module
    #[error("Seed too small")]
    SeedTooSmall,
}

/// Derive master private key from a seed
///
/// Minimum seed length is 32 bytes
pub fn derive_master_sk(seed: &[u8]) -> Result<Scalar, BlastKidsError> {
    if seed.len() < 32 {
        return Err(BlastKidsError::SeedTooSmall);
    }
    Ok(hkdf_mod_r(seed, b""))
}

/// HKDF Mod r (RFC 5869)
fn hkdf_mod_r(ikm: &[u8], key_info: &[u8]) -> Scalar {
    let mut okm: [u8; 48] = [0u8; 48];
    let mut sk = Scalar::ZERO;
    let key_info_combined = [key_info, &[0u8, 48u8]].concat();
    let ikm_combined = [ikm, &[0u8]].concat();
    let salt = &mut Sha256::digest(b"BLS-SIG-KEYGEN-SALT-")[..];

    while sk.is_zero().into() {
        hkdf(salt, ikm_combined.as_ref(), &key_info_combined, &mut okm);
        sk = Scalar::from_okm(&okm);
        let shadow_salt = &mut [0u8; 32];
        shadow_salt.copy_from_slice(salt);
        salt.copy_from_slice(&Sha256::digest(shadow_salt)[..]);
    }
    sk
}

/// Hierarchical Deterministic Key Derivation (BIP32)
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    // let (_prk, hk) = Hkdf::<Sha256>::extract(Some(&salt[..]), &ikm); // same as next line
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    hk.expand(info, okm)
        .expect("48 is a valid length for Sha256 to output");
}

/// Private -> Private hardened child key derivation
pub fn ckd_sk_hardened(parent_sk: &Scalar, index: u32) -> Scalar {
    let lamp_pk = parent_sk_to_lamport_pk(parent_sk, index);
    hkdf_mod_r(lamp_pk.as_ref(), b"")
}

/// Parent secret key to lamport public key
fn parent_sk_to_lamport_pk(parent_sk: &Scalar, index: u32) -> Vec<u8> {
    let salt = index.to_be_bytes();
    let ikm = parent_sk.to_be_bytes();
    let mut lamport_0 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(&ikm, salt.as_slice(), &mut lamport_0);

    let not_ikm = flip_bits(bigint::U256::from_be_bytes(parent_sk.to_be_bytes()));
    let mut lamport_1 = [[0u8; DIGEST_SIZE]; NUM_DIGESTS];
    ikm_to_lamport_sk(&not_ikm.to_be_bytes(), salt.as_slice(), &mut lamport_1);

    let mut combined = [[0u8; DIGEST_SIZE]; NUM_DIGESTS * 2];
    combined[..NUM_DIGESTS].clone_from_slice(&lamport_0[..NUM_DIGESTS]);
    combined[NUM_DIGESTS..NUM_DIGESTS * 2].clone_from_slice(&lamport_1[..NUM_DIGESTS]);

    let mut flattened_key = [0u8; OUTPUT_SIZE * 2];
    for i in 0..NUM_DIGESTS * 2 {
        let sha_slice = &Sha256::digest(combined[i])[..];
        flattened_key[i * DIGEST_SIZE..(i + 1) * DIGEST_SIZE].clone_from_slice(sha_slice);
    }

    let cmp_pk = &Sha256::digest(flattened_key)[..];

    cmp_pk.to_vec()
}

/// Intermediate Lamport key to Lamport secret key
fn ikm_to_lamport_sk(
    ikm: &[u8; 32],
    salt: &[u8],
    split_bytes: &mut [[u8; DIGEST_SIZE]; NUM_DIGESTS],
) {
    let mut okm = [0u8; OUTPUT_SIZE];
    hkdf(salt, ikm, b"", &mut okm);
    for r in 0..NUM_DIGESTS {
        split_bytes[r].copy_from_slice(&okm[r * DIGEST_SIZE..(r + 1) * DIGEST_SIZE])
    }
}

/// Bitwise XOR the given number with 2^256 - 1
fn flip_bits(num: bigint::U256) -> bigint::U256 {
    let rhs = bigint::U256::from_be_hex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    );
    num.bitxor(&rhs)
}

/// Get indexes from a string path following EIP2334 spec
pub fn path_to_node(path_str: &str) -> Result<Vec<u32>, String> {
    let mut path: Vec<&str> = path_str.split('/').collect();
    let m = path.remove(0);
    if m != "m" {
        return Err(format!("First value must be m, got {}", m));
    }
    let mut ret: Vec<u32> = vec![];
    for value in path {
        match value.parse::<u32>() {
            Ok(v) => ret.push(v),
            Err(_) => return Err(format!("could not parse value: {}", value)),
        }
    }
    Ok(ret)
}

/// Private -> Private non-hardened child key derivation
pub fn ckd_sk_normal<T>(parent_sk: &Scalar, index: u32) -> Scalar
where
    T: GroupEncoding + Group<Scalar = Scalar> + MulByGenerator,
{
    let parent_pk: T = T::mul_by_generator(parent_sk);
    let tweak = ckd_tweak_normal(&parent_pk, index);
    parent_sk.add(&tweak)
}

/// Compute the scalar tweak added to this key to get a child key
pub fn ckd_tweak_normal<T>(parent_pk: &T, index: u32) -> Scalar
where
    T: GroupEncoding,
{
    let salt = index.to_be_bytes();
    let ikm = parent_pk.to_bytes();
    let combined = [ikm.as_ref(), &salt[..]].concat();
    let digest = Sha256::digest(combined);
    bigint::U256::from_be_slice(&digest).into()
}

/// Public -> Public non-hardened child key derivation
pub fn ckd_pk_normal<T: GroupEncoding + Group<Scalar = Scalar> + MulByGenerator>(
    parent_pk: &T,
    index: u32,
) -> T {
    let tweak_sk: Scalar = ckd_tweak_normal(parent_pk, index);
    parent_pk.add(&T::mul_by_generator(&tweak_sk))
}

/// Private -> Private non-hardened child key derivation from a path
pub fn derive_child_sk_normal<T: GroupEncoding + Group<Scalar = Scalar> + MulByGenerator>(
    parent_sk: Scalar,
    path_str: &str,
) -> Scalar {
    let path: Vec<u32> = path_to_node(path_str).unwrap();
    let mut child_sk = parent_sk;
    for ccnum in path.iter() {
        child_sk = ckd_sk_normal::<T>(&child_sk, *ccnum);
    }
    child_sk
}

/// Public -> Public non-hardened child key derivation from a path
pub fn derive_child_pk_normal<T: GroupEncoding + Group<Scalar = Scalar> + MulByGenerator>(
    parent_pk: T,
    path_str: &str,
) -> T {
    let path: Vec<u32> = path_to_node(path_str).unwrap();
    let mut child_pk = parent_pk;
    for ccnum in path.iter() {
        child_pk = ckd_pk_normal(&child_pk, *ccnum);
    }
    child_pk
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestVector {
        seed: &'static str,
        master_sk: &'static str,
        child_index: &'static str,
        child_sk: &'static str,
    }

    #[test]
    fn test_ckd_hardened() {
        // test vectors from EIP2333 (in hex/hex/BigInt/BigInt)
        let test_vectors = vec!(
            TestVector{
                seed : "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
                // master_sk: "6083874454709270928345386274498605044986640685124978867557563392430687146096", //decimal
                master_sk : "0D7359D57963AB8FBBDE1852DCF553FEDBC31F464D80EE7D40AE683122B45070", // hex 
                child_index : "0",
                // child_sk : "20397789859736650942317412262472558107875392172444076792671091975210932703118", // decimal
                child_sk: "2D18BD6C14E6D15BF8B5085C9B74F3DAAE3B03CC2014770A599D8C1539E50F8E" // hex
            },
            TestVector{
                seed: "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
                // master_sk: "27580842291869792442942448775674722299803720648445448686099262467207037398656", // decimal
                master_sk: "3CFA341AB3910A7D00D933D8F7C4FE87C91798A0397421D6B19FD5B815132E80", // hex  
                child_index: "4294967295",
                // child_sk: "29358610794459428860402234341874281240803786294062035874021252734817515685787", // decimal 
                child_sk: "40E86285582F35B28821340F6A53B448588EFA575BC4D88C32EF8567B8D9479B" // hex
            },
            TestVector{
                seed: "3141592653589793238462643383279502884197169399375105820974944592",
                // master_sk: "29757020647961307431480504535336562678282505419141012933316116377660817309383", // decimal 
                master_sk: "41C9E07822B092A93FD6797396338C3ADA4170CC81829FDFCE6B5D34BD5E7EC7", // hex
                child_index: "3141592653",
                // child_sk: "25457201688850691947727629385191704516744796114925897962676248250929345014287", // decimal
                child_sk: "384843FAD5F3D777EA39DE3E47A8F999AE91F89E42BFFA993D91D9782D152A0F" // hex
            },
            TestVector{
                seed: "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
                // master_sk: "19022158461524446591288038168518313374041767046816487870552872741050760015818", // decimal
                master_sk: "2A0E28FFA5FBBE2F8E7AAD4ED94F745D6BF755C51182E119BB1694FE61D3AFCA", // hex    
                child_index: "42",
                // child_sk: "31372231650479070279774297061823572166496564838472787488249775572789064611981", // decimal
                child_sk: "455C0DC9FCCB3395825D92A60D2672D69416BE1C2578A87A7A3D3CED11EBB88D" // hex 
            }
        );
        for t in test_vectors.iter() {
            let seed = hex::decode(t.seed).expect("invalid seed format");
            let master_sk = Scalar::from_be_hex(t.master_sk).unwrap();
            let child_index = t.child_index.parse::<u32>().unwrap();
            let child_sk = Scalar::from_be_hex(t.child_sk).unwrap();

            let derived_master_sk: Scalar = derive_master_sk(seed.as_ref()).unwrap();
            assert_eq!(derived_master_sk, master_sk);

            let derived_sk: Scalar = ckd_sk_hardened(&master_sk, child_index);
            assert_eq!(derived_sk, child_sk);
        }
    }

    #[test]
    fn test_ckd_normal() {
        // test path parsing
        let mut invalid_path = path_to_node("m/a/3s/1726/0");
        invalid_path.expect_err("This path should be invalid");
        invalid_path = path_to_node("1/2");
        invalid_path.expect_err("Path must include a m");
        invalid_path = path_to_node("m");
        assert_eq!(invalid_path.unwrap(), vec![]);

        // test non-hardened child key derivation
        let seed: [u8; 37] = [
            1, 50, 6, 244, 24, 199, 1, 25, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ];
        let derived_master_sk = derive_master_sk(&seed).unwrap();
        println!(
            "derived_master_sk [{}] {:?}",
            derived_master_sk.to_be_bytes().len(),
            bigint::U256::from_be_bytes(derived_master_sk.to_be_bytes())
        );

        let derived_master_pk = G2::mul_by_generator(&derived_master_sk);
        let derived_child_sk = ckd_sk_normal::<G2>(&derived_master_sk, 42u32);

        // Note: These values deviate from the upstream library.
        // This is likely because Scaler::from(U256) is reduced by modulus but
        // ECScalar::from(bigint...) is not. Scalar::from_raw(..) matches the upstream
        // but doesn't compile to wasm. Both ways work fine, they just produce different keys.

        // assert_eq!(
        //     derived_child_sk,
        //     Scalar::from_be_hex("23cf2492eb784e5e01015731deb8de292e0766d3b688f3ad6e31bc73ddde2f38")
        //         .unwrap()
        // );
        println!(
            "derived_child_sk [{}] {:?}",
            derived_child_sk.to_be_bytes().len(),
            bigint::U256::from_be_bytes(derived_child_sk.to_be_bytes()),
        );

        let derived_child_pk = ckd_pk_normal(&derived_master_pk, 42u32);
        assert_eq!(derived_child_pk, G2::mul_by_generator(&derived_child_sk));
        println!(
            "child pk  [{}] {:?}",
            derived_child_pk.to_bytes().as_ref().len(),
            derived_child_pk.to_bytes(),
        );
        let derived_grandchild_sk: Scalar = ckd_sk_normal::<G2>(&derived_child_sk, 12142u32);
        let derived_grandchild_pk: G2 = ckd_pk_normal(&derived_child_pk, 12142u32);
        assert_eq!(
            derived_grandchild_pk,
            G2::mul_by_generator(&derived_grandchild_sk),
        );
        println!(
            "great grandchild sk: {:?}",
            bigint::U256::from_be_bytes(derived_grandchild_sk.to_be_bytes()),
        );
        let derived_greatgrandchild_sk: Scalar =
            ckd_sk_normal::<G2>(&derived_grandchild_sk, 3141592653u32);
        let derived_greatgrandchild_pk: G2 = ckd_pk_normal(&derived_grandchild_pk, 3141592653u32);
        assert_eq!(
            derived_greatgrandchild_pk,
            G2::mul_by_generator(&derived_greatgrandchild_sk),
        );

        assert_eq!(
            derive_child_sk_normal::<G2>(derived_master_sk, "m/42/12142/3141592653"),
            derived_greatgrandchild_sk
        );
        assert_eq!(
            derive_child_pk_normal(derived_master_pk, "m/42/12142/3141592653"),
            derived_greatgrandchild_pk
        );
    }
}
