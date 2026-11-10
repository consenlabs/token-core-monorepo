import { spawnSync } from "node:child_process";

// Reviewed host-only tests. Hardware tests remain runnable in test-hardware;
// do not infer safety from names or add blanket #[ignore] attributes.
const suites = {
  "coin-bitcoin": [
    "common::test::get_address_version_test",
    "address::test::get_parent_path_test",
    "address::test::get_parent_path_path_is_empty_test",
    "psbt::test::sign_rejects_missing_pub_keys_before_partial_signing",
    "psbt::test::taproot_path_selection_is_scoped_to_the_current_input",
    "psbt::test::taproot_multi_leaf_selection_uses_bip371_key_origins",
    "transaction::tests::async_tx_output_uses_async_transport_for_taproot_change_address",
    "transaction::tests::async_tx_output_covers_btc_and_doge_change_modes",
    "usdt_transaction::tests::exceeded_max_utxo_number_test",
    "usdt_transaction::tests::amount_less_than_minimum_test",
  ],
  "coin-btc-fork": [
    "address::test::test_p2pkh_from_pub_key_uses_compressed_serialization",
    "address::test::test_btc_fork_address_from_str",
    "transaction::tests::async_change_address_uses_transport_for_ltc_legacy_and_segwit",
  ],
  "coin-bch": [
    "address::tests::test_convert",
    "address::tests::is_valid_accepts_legacy_and_cash_addresses",
    "common::test::get_address_version_test",
    "transaction::tests::async_change_address_uses_transport_and_propagates_failure",
    "transaction::tests::checked_amounts_reject_insufficient_funds_and_overflow",
    "transaction::tests::checked_amounts_preserve_zero_and_dust_change",
    "transaction::tests::build_send_to_output_rejects_invalid_address",
    "transaction::tests::sign_response_payload_requires_a_compact_signature",
    "transaction::tests::get_change_address_accepts_legacy_bch_address",
  ],
  "coin-ckb": [
    "address::tests::test_from_public_key",
    "serializer::tests::serialize_struct",
    "serializer::tests::serialize_fixed_vec",
    "serializer::tests::serialize_dynamic_vec",
    "transaction_helper::tests::serialize_script",
    "transaction_helper::tests::script_to_hash",
    "transaction_helper::tests::serialize_witness",
    "transaction_helper::tests::witness_to_raw",
    "tests::hex_convert",
  ],
  "coin-cosmos": ["address::tests::test_bech32", "transaction::tests::test_ecsign", "transaction::tests::test_base64", "transaction::tests::test_sort_vec"],
  "coin-eos": ["pubkey::tests::pubkey_from_response"],
  "coin-ethereum": ["address::test::test_pubkey_to_address", "address::test::test_checksummed_address", "transaction::tests::test_retrieve_recid"],
  "coin-filecoin": ["utils::tests::test_digest"],
  "coin-substrate": ["address::test::test_address_from_public"],
  "coin-tron": ["address::tests::tron_address"],
};

for (const [crate, tests] of Object.entries(suites)) {
  const args = ["test", "-p", crate, "--lib", "--"];
  const list = spawnSync("cargo", [...args, "--list"], { encoding: "utf8" });
  if (list.status !== 0) { process.stderr.write(list.stderr); process.exit(list.status ?? 1); }
  for (const test of tests) {
    if (!list.stdout.split("\n").includes(`${test}: test`)) throw new Error(`Missing host test: ${crate} ${test}`);
  }
  const result = spawnSync("cargo", [...args, "--exact", "--test-threads=1", ...tests], { stdio: "inherit" });
  if (result.status !== 0) process.exit(result.status ?? 1);
}
