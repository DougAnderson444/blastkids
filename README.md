# Blastkids 🚀🔑🔑🔑

[![GitHub Workflow Status](https://img.shields.io/github/workflow/status/DougAnderson444/blastkids/Rust)](

[![Build Status](https://travis-ci.com/DougAnderson444/blastkids.svg?branch=master)](https://travis-ci.com/DougAnderson444/blastkids)
[![codecov](https://codecov.io/gh/DougAnderson444/blastkids/branch/master/graph/badge.svg)](https://codecov.io/gh/DougAnderson444/blastkids)
[![Crates.io](https://img.shields.io/crates/v/blastkids.svg)](https://crates.io/crates/blastkids)
[![Docs.rs](https://docs.rs/blastkids/badge.svg)](https://docs.rs/blastkids)
[![dependency status](https://deps.rs/repo/github/DougAnderson444/blastkids/status.svg)](https://deps.rs/repo/github/DougAnderson444/blastkids)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

A BLS12-381 child key derivation library written in Rust. Implements EIP-2333 and EIP-2334.

Fork of [rust-bls-derivation](https://github.com/taiyi-research-institute/rust-bls-derivation) using [`bls12_381_plus`](https://github.com/mikelodder7/bls12_381_plus) instead of [`curv-kzen`](https://crates.io/crates/curv-kzen), plus cleanup and documentation.

## Rationale

If you want to use Delegatable Anonymous Credentials the verification key (`VK`) becomes as long as the credential entries. Since a `VK` is simply several BLS12-381 public keys (`PK`s) we can use a derivation algorithm such as EIP-2333 in order to derive the long `VK` from a single root `PK` given any length.

## Installation

```bash
cargo install blastkids
```

## API & Docs

See documentation on [docs.rs](https://docs.rs/blastkids).

See tests in [`lib.rs`](./src/lib.rs) for example usage.

```rust
use blastkids::{Manager, Seed, derive};
use blastkids::{G1, G2};

// make a new manager for a G2 public key
let seed = Seed::new([42u8; 32]);
let manager: Manager<G2> = Manager::from_seed(seed);

// With a Manager you can create as many account sas you need
let account_number = 1u32;
let account = manager.account(account_number);

let length = 8u8; // Specify how many Child Public Keys you need (in this case, 8). Can be up to 255.

// Anyone can use an Account Public Key and a `length` to derive a child account
let child_account: Vec<G2> = derive(&account.pk, length);

// When you want to use the child account secret keys,
// you call `sized` on the account
let child = account.sized(length);

// This child public keys are the same as the ones derived above
assert_eq!(child.pk, child_account);
```

## Tests

```bash
cargo test
```

## Dependencies

- BLS12-381: [bls12_381_plus](https://crates.io/crates/bls12_381_plus)
- Elliptic Curve: [RustCrypto/elliptic-curves](https://crates.io/crates/elliptic-curve)
- Big Integers: [RustCrypto/ctypro-bigint](https://crates.io/crates/crypto-bigint)

## See also

- Generate seeds using `password` + `salt`: [seed-keeper-core](https://github.com/DougAnderson444/seed-keeper)
- Generate Credentials using a `seed`: [delanocreds](https://github.com/DougAnderson444/delanocreds)

## Prior Work

- [EIP-2333](https://eips.ethereum.org/EIPS/eip-2333)
- [EIP-2334](https://eips.ethereum.org/EIPS/eip-2334)
- [rust-bls-derivation](https://github.com/taiyi-research-institute/rust-bls-derivation) (circa 2023, uses [`curv-kzen`](https://crates.io/crates/curv-kzen) library which breaks with rust-nightly and appears somewhat unmaintained)

## Contributing

Contributions are welcome! Please open an issue if you have any feature ideas or find any bugs. I also accept pull requests with open arms. Please:

1. Fork this repo
2. Create a new branch for your changes
3. Open a draft pull request so we can follow and collaborate on your changes
4. Add tests for your changes
5. Keep the diff minimal for each pull request
6. Write meaningful commit messages
7. Change Draft to Open when you're ready for final review
