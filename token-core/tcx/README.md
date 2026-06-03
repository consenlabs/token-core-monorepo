# TokenCoreX API Layer

This package is used to exposed all API.

## Security-sensitive features

The default build keeps test/debug-only methods out of `call_tcx_api`.

- `cache_dk`: enables `get_derived_key` for explicit derived-key cache integrations.
- `test_api`: enables `unlock_then_crash` for panic/lock-state tests only.

Production builds should not enable `test_api`. New callers should prefer
`sign_transaction`, `sign_message`, and `sign_raw_hashes`; legacy aliases
`sign_tx`, `sign_msg`, and `sign_hashes` remain available for compatibility.
