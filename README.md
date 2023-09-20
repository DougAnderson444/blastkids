# Blastkids

[![Build Status](https://travis-ci.com/DougAnderson444/blastkids.svg?branch=master)](https://travis-ci.com/DougAnderson444/blastkids)
[![codecov](https://codecov.io/gh/DougAnderson444/blastkids/branch/master/graph/badge.svg)](https://codecov.io/gh/DougAnderson444/blastkids)
[![Crates.io](https://img.shields.io/crates/v/blastkids.svg)](https://crates.io/crates/blastkids)
[![Docs.rs](https://docs.rs/blastkids/badge.svg)](https://docs.rs/blastkids)
[![dependency status](https://deps.rs/repo/github/DougAnderson444/blastkids/status.svg)](https://deps.rs/repo/github/DougAnderson444/blastkids)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A BLS12-381 child key derivation library written in Rust. Implements EIP-2333 and EIP-2334. Fork of [rust-bls-derivation](https://github.com/taiyi-research-institute/rust-bls-derivation) using [`bls12_381_plus`](https://github.com/mikelodder7/bls12_381_plus) instead of [`curv-kzen`](https://crates.io/crates/curv-kzen)

## Rationale

If you want to use Delegatable Anonymous Credentials the verification key (VK) becomes long. Since a VK is simply several BLS12-381 public keys (PKs) we can use a derivation algorithm such as EIP-2333 in order to derive the long VK from a single root PK given any length:written.

## Installation

```bash
cargo install blastkids
```

## API

See tests in [`/lib.rs`] for examples.

## Tests

```bash
cargo test
```

## Dependencies

Uses:

- BLS12-381: [bls12_381_plus](https://crates.io/crates/bls12_381_plus)
- Elliptic Curve: [RustCrypto/elliptic-curves](https://crates.io/crates/elliptic-curve)
- Big Integers: [RustCrypto/ctypro-bigint](https://crates.io/crates/crypto-bigint)

## See also

- Generate seeds using password + salt: [seed-keeper-core](https://github.com/DougAnderson444/seed-keeper)
- Generate Credentials using a seed: [delanocreds](https://github.com/DougAnderson444/delanocreds)

## Prior Work

- [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333)
- [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334)
- [rust-bls-derivation](https://github.com/taiyi-research-institute/rust-bls-derivation) (circa 2023, uses [`curv-kzen`](https://crates.io/crates/curv-kzen) library which breaks with rust-nightly and appears somewhat unmaintained)
