# ImKeyCore

Next generation core inside imKey Wallet.

WARNING: not production ready yet.

## Goals
* Unify interface for wallet common logic with multi blockchain support
* Cross platform, on mobile, desktop, server side

## Layout
* `api` wallet interface wrapper
* `wallet` packages contain particular chain logic(address & signer)
* `common` | `transport` common interface
* `common` imKey management function
* `mobile-sdk` mobile sdk 


## Test Coverage
We can use [tarpaulin](https://github.com/xd009642/tarpaulin) to know the coverage rate.

The easy way to run coverage test is using docker,

```
docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin sh -c "cargo tarpaulin --out Html"
```

After couple minutes, it will generate html report of project root directory named `tarpaulin-report.html`.

## Code Styles
This project is using pre-commit. Please run `cargo clean && cargo test` to install the git pre-commit hooks on you clone.

Every time you will try to commit, pre-commit will run checks on your files to make sure they follow our style standards
and they aren't affected by some simple issues. If the checks fail, pre-commit won't let you commit.

## Mobile-SDK

Mobile-SDK is built to provide an easy interface to the native imkey-core libraries on both iOS and Andoird.

[Mobile-SDK](mobile-sdk/README.md)

## Read More
* [How to build project](docs/BUILD.zh.md)
* [Architecture design](docs/TECH.zh.md)
* [flow chart](docs/flowchart/)

## License
Apache Licence v2.0
