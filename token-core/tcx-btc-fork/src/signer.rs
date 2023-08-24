use tcx_chain::{Keystore, TransactionSigner};

use bitcoin::{
    EcdsaSighashType, OutPoint, PackedLockTime, PubkeyHash, Script, Sequence, SigHashType, Sighash,
    Transaction, TxIn, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::Hash;

use crate::Result;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::serialize;
use std::str::FromStr;

use crate::address::BtcForkAddress;
use crate::transaction::{BtcForkSignedTxOutput, BtcForkTxInput, Utxo};
use bitcoin::blockdata::opcodes::all::OP_PUSHBYTES_22;
use bitcoin::util::sighash::SighashCache;
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::FromHex as HashFromHex;
use bitcoin_hashes::hex::ToHex as HashToHex;
use std::marker::PhantomData;
use std::ops::Deref;
use tcx_chain::keystore::Error;
use tcx_chain::Address;
use tcx_constants::CoinInfo;
use tcx_primitive::{
    Bip32DeterministicPublicKey, Derive, DeterministicPublicKey, FromHex, PrivateKey, PublicKey,
    Secp256k1PrivateKey, TypedDeterministicPublicKey, TypedPrivateKey,
};

const DUST: u64 = 546;
const SIGHASH_ALL: u8 = 0x01;

pub trait ScriptPubKeyComponent {
    fn address_script_like(target_addr: &str, pub_key: &bitcoin::PublicKey) -> Result<Script>;
    fn address_script_pub_key(target_addr: &str) -> Result<Script>;
}

pub struct SigningContext<'a> {
    tx: Transaction,
    pub private_keys: Vec<Secp256k1PrivateKey>,
    pub sighash_cache: SighashCache<&'a Transaction>,
}

pub struct KinTransaction {
    unspent: Vec<Utxo>,
    amount: i64,
    fee: i64,
    to: Script,
    change_script: Script,
}

impl KinTransaction {
    fn hash160(&self, input: &[u8]) -> hash160::Hash {
        hash160::Hash::hash(input)
    }

    fn sign_p2pkh_input(&self, context: &mut SigningContext, index: usize) -> Result<()> {
        let key = &context.private_keys[index];
        let script = Script::new_p2pkh(&PubkeyHash::from_hash(
            self.hash160(&key.public_key().to_bytes()),
        ));

        let hash = context.sighash_cache.legacy_signature_hash(
            index,
            &script,
            EcdsaSighashType::All.to_u32(),
        )?;
        let sig = key.sign(&hash)?;

        let sig = [sig, vec![1]].concat();

        context.tx.input[index].script_sig = Builder::new()
            .push_slice(&sig)
            .push_slice(&key.public_key().to_bytes())
            .into_script();

        Ok(())
    }

    pub fn sign_p2sh_nested_p2wpkh_input(
        &self,
        context: &mut SigningContext,
        index: usize,
    ) -> Result<()> {
        let unspent = &self.unspent[index];
        let key = &context.private_keys[index];
        let pub_key = key.public_key();

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(
            self.hash160(&pub_key.to_compressed()),
        ));

        let hash = context.sighash_cache.segwit_signature_hash(
            index,
            &script.p2wpkh_script_code().expect("must be v0_p2wpkh"),
            unspent.amount as u64,
            EcdsaSighashType::All,
        )?;
        let sig = key.sign(&hash)?;

        let mut tx_input = &mut context.tx.input[index];

        tx_input.witness.push(sig);
        tx_input.witness.push(pub_key.to_bytes());
        tx_input.script_sig = Builder::new()
            .push_opcode(OP_PUSHBYTES_22)
            .push_slice(script.as_bytes())
            .into_script();

        Ok(())
    }

    pub fn sign_p2wpkh_input(&self, context: &mut SigningContext, index: usize) -> Result<()> {
        let key = &context.private_keys[index];
        let unspent = &self.unspent[index];
        let pub_key = key.public_key();

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(
            self.hash160(&pub_key.to_compressed()),
        ));

        let hash = context.sighash_cache.segwit_signature_hash(
            index,
            &script,
            unspent.amount as u64,
            EcdsaSighashType::All,
        )?;
        let sig = key.sign(&hash)?;

        let mut tx_input = &mut context.tx.input[index];

        tx_input.witness.push(sig);
        tx_input.witness.push(pub_key.to_bytes());

        Ok(())
    }

    pub fn sign_p2tr_input(&self, context: &mut SigningContext, index: usize) -> Result<()> {
        unimplemented!()
    }

    fn tx_outs(&self) -> Result<Vec<TxOut>> {
        let mut total_amount = 0;

        for unspent in &self.unspent {
            total_amount += unspent.amount;
        }

        ensure!(self.amount >= DUST as i64, "amount_less_than_minimum");

        ensure!(
            total_amount >= (self.amount + self.fee),
            "total amount must ge amount + fee"
        );

        let mut tx_outs: Vec<TxOut> = vec![];

        tx_outs.push(TxOut {
            value: self.amount as u64,
            script_pubkey: self.to.clone(),
        });

        let change_amount = total_amount - self.amount - self.fee;

        if change_amount >= DUST as i64 {
            tx_outs.push(TxOut {
                value: change_amount as u64,
                script_pubkey: self.change_script.clone(),
            });
        }
        Ok(tx_outs)
    }

    pub fn sign(
        &self,
        version: i32,
        private_keys: Vec<Secp256k1PrivateKey>,
    ) -> Result<BtcForkSignedTxOutput> {
        let tx_input = self
            .unspent
            .iter()
            .map(|x| TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&x.tx_hash).expect("tx_hash"),
                    vout: x.vout as u32,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            })
            .collect::<Vec<TxIn>>();

        let tx_outs = self.tx_outs()?;

        let tx = Transaction {
            version,
            lock_time: PackedLockTime::ZERO,
            input: tx_input.clone(),
            output: tx_outs.clone(),
        };

        let tx_clone = Transaction {
            version,
            lock_time: PackedLockTime::ZERO,
            input: tx_input,
            output: tx_outs,
        };

        let mut context = SigningContext {
            tx,
            private_keys,
            sighash_cache: SighashCache::new(&tx_clone),
        };

        for idx in 0..self.unspent.len() {
            let unspent = &self.unspent[idx];
            let script =
                bitcoin::util::address::Address::from_str(&unspent.address)?.script_pubkey();
            if script.is_p2pkh() {
                self.sign_p2pkh_input(&mut context, idx)?;
            } else if script.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh_input(&mut context, idx)?;
            } else if script.is_v0_p2wpkh() {
                self.sign_p2wpkh_input(&mut context, idx)?;
            } else if script.is_v1_p2tr() {
                self.sign_p2tr_input(&mut context, idx)?;
            }
        }

        let tx_bytes = serialize(&context.tx);
        let tx_hash = context.tx.txid().to_hex();

        Ok(BtcForkSignedTxOutput {
            signature: tx_bytes.to_hex(),
            tx_hash,
        })
    }
}

impl TransactionSigner<BtcForkTxInput, BtcForkSignedTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &BtcForkTxInput,
    ) -> Result<BtcForkSignedTxOutput> {
        let account = self
            .account(symbol, address)
            .ok_or(Error::AccountNotFound)?;
        let coin_info = account.coin_info();

        let change_script = if !tx.change_address.is_empty() {
            bitcoin::util::address::Address::from_str(&tx.change_address)?.script_pubkey()
        } else if self.determinable() {
            let dpk = account.deterministic_public_key()?;
            let pub_key = dpk
                .derive(format!("1/{}", tx.change_address_index).as_str())?
                .public_key();
            let change_address = BtcForkAddress::from_public_key(&pub_key, &coin_info)?;

            bitcoin::util::address::Address::from_str(&change_address)?.script_pubkey()
        } else {
            bitcoin::util::address::Address::from_str(address)?.script_pubkey()
        };

        let to = bitcoin::util::address::Address::from_str(&tx.to)?.script_pubkey();

        let mut sks = vec![];
        for x in tx.unspents.iter() {
            if x.derived_path.len() > 0 {
                sks.push(
                    self.find_private_key_by_path(symbol, address, &x.derived_path)?
                        .as_secp256k1()?
                        .clone(),
                );
            } else {
                sks.push(
                    self.find_private_key(symbol, &x.address)?
                        .as_secp256k1()?
                        .clone(),
                );
            }
        }

        let kin_tx = KinTransaction {
            unspent: tx.unspents.clone(),
            amount: tx.amount,
            fee: tx.fee,
            to,
            change_script,
        };

        kin_tx.sign(1 as i32, sks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::address::BtcForkAddress;
    use tcx_chain::Metadata;
    use tcx_chain::{Keystore, TransactionSigner};
    use tcx_constants::coin_info::coin_info_from_param;
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_primitive::Secp256k1PrivateKey;

    mod btc {
        use super::*;
        use tcx_constants::CurveType;

        #[test]
        fn sign_op_return_with_keystore() {
            let mut ks =
                Keystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
            let guard = ks.unlock_by_password(TEST_PASSWORD).unwrap();

            let unspent = vec![
                Utxo {
                    tx_hash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                        .to_string(),
                    vout: 0,
                    amount: 50000,
                    address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                    script_pub_key: "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987".to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                },
                Utxo {
                    tx_hash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                        .to_string(),
                    vout: 0,
                    amount: 50000,
                    address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                    script_pub_key: "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787".to_string(),
                    derived_path: "0/1".to_string(),
                    sequence: 0,
                },
            ];

            let tx_input = BtcForkTxInput {
                to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
                amount: 88000,
                unspents: unspent,
                fee: 12000,
                change_address_index: 53u32,
                change_address: "".to_string(),
                network: "MAINNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let coin_info = coin_info_from_param("BITCOIN", "TESTNET", "NONE", "").unwrap();
            /*
                       let tran = BitcoinForkSinger::<BtcForkAddress, SegWitTransactionSignComponent> {
                           tx_input,
                           coin_info,
                           _marker_s: PhantomData,
                           _marker_t: PhantomData,
                       };
                       let expected = ks
                           .sign_transaction("BITCOIN", "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", &tran)
                           .unwrap();
                       //            assert_eq!(expected.signature, "");
            */
        }

        #[test]
        fn sign_with_keystore_on_testnet() {
            let mut ks =
                Keystore::from_mnemonic(TEST_MNEMONIC, TEST_PASSWORD, Metadata::default()).unwrap();
            let guard = ks.unlock_by_password(TEST_PASSWORD).unwrap();

            let unspent = vec![
                Utxo {
                    tx_hash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                        .to_string(),
                    vout: 0,
                    amount: 200000000,
                    address: "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC".to_string(),
                    script_pub_key: "76a914118c3123196e030a8a607c22bafc1577af61497d88ac"
                        .to_string(),
                    derived_path: "0/22".to_string(),
                    sequence: 0,
                },
                Utxo {
                    tx_hash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                        .to_string(),
                    vout: 1,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                },
                Utxo {
                    tx_hash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                        .to_string(),
                    vout: 0,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                },
                Utxo {
                    tx_hash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                        .to_string(),
                    vout: 1,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                },
            ];

            let tx_input = BtcForkTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 799988000,
                unspents: unspent.clone(),
                fee: 12000,
                change_address_index: 53u32,
                change_address: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let coin_info = coin_info_from_param("BITCOIN", "TESTNET", "NONE", "").unwrap();
            ks.derive_coin::<BtcForkAddress>(&coin_info);

            let expected = ks
                .sign_transaction("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            //            assert_eq!(expected.signature, "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c610f77f71cc8afcfbd46df8e3d564fb8fb0f2c041bdf0869512c461901a8ad802206b92460cccbcb2a525877db1b4b7530d9b85e135ce88424d1f5f345dc65b881401210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100dce4a4c3d79bf9392832f68da3cd2daf85ac7fa851402ecc9aaac69b8761941d02201e1fd6601812ea9e39c6df0030cb754d4c578ff48bc9db6072ba5207a4ebc2b60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100e1802d80d72f5f3be624df3ab668692777188a9255c58067840e4b73a5a61a99022025b23942deb21f5d1959aae85421299ecc9efefb250dbacb46a4130abd538d730121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a47304402207b82a62ed0d35c9878e6a7946d04679c8a17a8dd0a856b5cc14928fe1e9b554a0220411dd1a61f8ac2a8d7564de84e2c8a2c2583986bd71ac316ade480b8d0b4fffd0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0120d9ae2f000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac00000000");

            let tx_input = BtcForkTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 750000000,
                unspents: unspent,
                fee: 502130,
                change_address_index: 53u32,
                change_address: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            //contains change
            let coin_info = coin_info_from_param("BITCOIN", "TESTNET", "NONE", "").unwrap();
            let expected = ks
                .sign_transaction("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();

            //see https://mempool.space/testnet/tx/3aa6ed94e29c01b96fe3a20c30825d161f421d5e2358eb1ceade43de533e1977#vin=0
            assert_eq!(
                expected.tx_hash,
                "3aa6ed94e29c01b96fe3a20c30825d161f421d5e2358eb1ceade43de533e1977"
            );
            assert_eq!(expected.signature, "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c4f39ce7f2448ab8e7154a7b7ce82edd034e3f33e1f917ca43e4aff822ba804c02206dd146d1772a45bb5e51abb081d066114e78bcb504671f61c5a301a647a494ac01210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100d235afda9a56aaa4cbe05df712202e6b1a45aab7a0c83540d3053133f15acc5602201b0e144bec3a02a5c556596040b0be81b0202c19b163bb537b8d965afd61403a0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100dd8f1e20116f96a3400f55e0c637a0ad21ae47ff92d83ffb0c3d324c684a54be0220064b0a6d316154ef07a69bd82de3a052e43c3c6bb0e55e4de4de939b093e1a3a0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a473044022048d8cb0f1480174b3b9186cc6fe410db765f1f9d3ce036b0d4dee0eb19aa3641022073de4bb2b00a0533e9c8f3e074c655e0695c8b223233ddecf3c99a84351d50a60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff028017b42c000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac0e47f302000000001976a91412967cdd9ceb72bbdbb7e5db85e2dbc6d6c3ab1a88ac00000000");
        }
    }

    mod ltc {
        use super::*;

        /*
        #[test]
        fn test_sign() {
            let unspents = vec![Utxo {
                tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
                derived_path: "0/0".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
                amount: 500000,
                unspents,
                fee: 100000,
                change_address_index: 1u32,
                change_address: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };
            let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
            let tran = BitcoinForkSinger::<
                BtcForkAddress,
                LegacyTransactionSignComponent<LegacySignHasher>,
            > {
                tx_input,
                coin_info,
                _marker_s: PhantomData,
                _marker_t: PhantomData,
            };

            let prv_key = Secp256k1PrivateKey::from_wif(
                "cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY",
            )
            .unwrap();
            let change_addr =
                BtcForkAddress::from_str("mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up").unwrap();
            let expected = tran
                .sign_transaction(&vec![prv_key], change_addr.script_pubkey())
                .unwrap();
            assert_eq!(expected.signature, "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006a473044022029063983b2537e4aa15ee838874269a6ba6f5280297f92deb5cd56d2b2db7e8202207e1581f73024a48fce1100ed36a1a48f6783026736de39a4dd40a1ccc75f651101210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5effffffff0220a10700000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac801a0600000000001976a914073b7eae2823efa349e3b9155b8a735526463a0f88ac00000000");
        }
         */

        #[test]
        fn test_sign_ltc_from_keystore() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let unspents = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derived_path: "0/0".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                unspents,
                fee: 5902,
                change_address_index: 1u32,
                change_address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let expected = keystore
                .sign_transaction("LITECOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_eq!(
                expected.tx_hash,
                "f90dd185c2a14fa29b9644f4087eecf64fd87d5c60f8e36f790054a4b55450e1"
            );
            assert_eq!(expected.signature, "010000000101a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006b48304502210090beb741ec38b0931a457c40086ba183c0cc85542bce5e5811a2377e954a113b022029a37ba9ccfe57fc77f639c7599d4fcf35f2fb921a610967a88dba0a800ee9ae0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02a0860100000000001976a914461bf9360ec1bc9fe438df19ef36c7c2bb26ef8288ac92a40d00000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac00000000");
        }

        #[test]
        fn test_sign_ltc_multi_utxo() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let unspents = vec![
                Utxo {
                    tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                },
                Utxo {
                    tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a100"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                },
            ];
            let tx_input = BtcForkTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 1100000,
                unspents,
                fee: 5902,
                change_address_index: 1u32,
                change_address: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let expected = keystore
                .sign_transaction("LITECOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_eq!(
                expected.tx_hash,
                "96fe3a5ff0e01e533f19642a0bd05ed4925dfdc271124bc08c3aa4a8bdb9d5c8"
            );

            assert_eq!(expected.signature, "010000000201a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006b483045022100a49798664e490075f9d111c6b6e8541781a5a88df1b95eb910dd307298ead4e802203adb4a21f2e680e1d05f6346ec25b1077f60e58c6289606cc9dad15698b5368d0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff00a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006a473044022100c7e2dba307022d45067e7b3eceb2b288f49037f43c8bac271ccc831f250b9438021f14103613f41f6d6811f70359077ae96dc2055fcb9dd5aff21469e1fb51a9870121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02e0c81000000000001976a914461bf9360ec1bc9fe438df19ef36c7c2bb26ef8288ac92a40d00000000001976a9143770c8c6671d27e2a9f4502d74932bf740c1ff8688ac00000000");
        }

        #[test]
        fn test_wrong_derived_path() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let unspents = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derived_path: "0/1".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                unspents,
                fee: 5902,
                change_address_index: 1u32,
                change_address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let expected = keystore
                .sign_transaction("LITECOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_ne!(
                expected.tx_hash,
                "f90dd185c2a14fa29b9644f4087eecf64fd87d5c60f8e36f790054a4b55450e1"
            );
            assert_ne!(expected.signature, "010000000101a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006b48304502210090beb741ec38b0931a457c40086ba183c0cc85542bce5e5811a2377e954a113b022029a37ba9ccfe57fc77f639c7599d4fcf35f2fb921a610967a88dba0a800ee9ae0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02a0860100000000001976a914461bf9360ec1bc9fe438df19ef36c7c2bb26ef8288ac92a40d00000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac00000000");
        }

        #[test]
        fn test_invalid_derived_path() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let unspents = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derived_path: "hello//ggg".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                unspents,
                fee: 5902,
                change_address_index: 1u32,
                change_address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let ret = keystore.sign_transaction(
                "LITECOIN",
                "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                &tx_input,
            );
            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "invalid child number format"
            );
        }

        #[test]
        fn test_sign_ltc_invalid_unspent_address() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let unspents = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "address_invalid".to_string(),
                script_pub_key: "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac".to_string(),
                derived_path: "0/0".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                unspents,
                fee: 5902,
                change_address_index: 1u32,
                change_address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let ret = keystore.sign_transaction(
                "LITECOIN",
                "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                &tx_input,
            );
            assert!(ret.is_err());
        }

        #[test]
        fn test_sign_ltc_amount_great_than_unspents() {
            // amount great than unspents
            let unspents = vec![Utxo {
                tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
                derived_path: "0/0".to_string(),
                sequence: 0,
            }];
            let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
            let tx_input = BtcForkTxInput {
                to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
                amount: 1500000,
                unspents,
                fee: 100000,
                change_address_index: 1u32,
                change_address: "mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };

            let prv_key = Secp256k1PrivateKey::from_wif(
                "cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY",
            )
            .unwrap()
            .to_bytes()
            .to_hex();

            let mut keystore =
                Keystore::from_private_key(&prv_key, TEST_PASSWORD, Metadata::default());
            let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
            let _ = keystore.unlock_by_password(TEST_PASSWORD).unwrap();
            keystore.derive_coin::<BtcForkAddress>(&coin_info);

            let ret = keystore.sign_transaction(
                "LITECOIN",
                "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1",
                &tx_input,
            );
            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "total amount must ge amount + fee"
            );
        }

        /*
        #[test]
        fn test_sign_ltc_amount_less_than_dust() {
            // amount great than unspents
            let unspents = vec![Utxo {
                tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
                derived_path: "0/0".to_string(),
                sequence: 0,
            }];
            let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
            let tx_input = BtcForkTxInput {
                to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
                amount: 545,
                unspents,
                fee: 100000,
                change_address_index: 1u32,
                change_address: "".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };
            let tran = BitcoinForkSinger::<
                BtcForkAddress,
                LegacyTransactionSignComponent<LegacySignHasher>,
            > {
                tx_input,
                coin_info,
                _marker_s: PhantomData,
                _marker_t: PhantomData,
            };

            let prv_key = Secp256k1PrivateKey::from_wif(
                "cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY",
            )
            .unwrap();
            let change_addr =
                BtcForkAddress::from_str("mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up").unwrap();
            let ret = tran.sign_transaction(&vec![prv_key], change_addr.script_pubkey());
            assert!(ret.is_err());
            assert_eq!(
                format!("{}", ret.err().unwrap()),
                "amount_less_than_minimum"
            );
        }*/

        /*
        #[test]
        fn test_sign_ltc_invalid_ltc_to_address() {
            let chain_types = vec!["BITCOINCASH", "LITECOIN"];
            for chain_type in chain_types {
                let unspents = vec![Utxo {
                    tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                    script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                    sequence: 0,
                }];
                let coin_info = coin_info_from_param(chain_type, "TESTNET", "NONE", "").unwrap();
                let tx_input = BtcForkTxInput {
                    to: "address_invalid".to_string(),
                    amount: 500000,
                    unspents,
                    fee: 100000,
                    change_address_index: 1u32,
                    change_address: "".to_string(),
                    network: "TESTNET".to_string(),
                    seg_wit: "NONE".to_string(),
                };
                let tran = BitcoinForkSinger::<
                    BtcForkAddress,
                    LegacyTransactionSignComponent<LegacySignHasher>,
                > {
                    tx_input,
                    coin_info,
                    _marker_s: PhantomData,
                    _marker_t: PhantomData,
                };

                let prv_key = Secp256k1PrivateKey::from_wif(
                    "cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY",
                )
                .unwrap();
                let change_addr =
                    BtcForkAddress::from_str("mgBCJAsvzgT2qNNeXsoECg2uPKrUsZ76up").unwrap();
                let ret = tran.sign_transaction(&vec![prv_key], change_addr.script_pubkey());
                assert!(ret.is_err());
            }
        }*/

        /*
        #[test]
        fn test_sign_ltc_change_address() {
            let unspents = vec![Utxo {
                tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
                derived_path: "0/0".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
                amount: 500000,
                unspents,
                fee: 100000,
                change_address_index: 0,
                change_address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                network: "TESTNET".to_string(),
                seg_wit: "NONE".to_string(),
            };
            let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
            let tran = BitcoinForkSinger::<
                BtcForkAddress,
                LegacyTransactionSignComponent<LegacySignHasher>,
            > {
                tx_input,
                coin_info,
                _marker_s: PhantomData,
                _marker_t: PhantomData,
            };

            let prv_key = Secp256k1PrivateKey::from_wif(
                "cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY",
            )
            .unwrap();
            let change_addr =
                BtcForkAddress::from_str("mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1").unwrap();
            let actual = tran
                .sign_transaction(&vec![prv_key], change_addr.script_pubkey())
                .unwrap();
            assert_eq!(actual.signature, "01000000015884e5db9de218238671572340b207ee85b628074e7e467096c267266baf77a4000000006b483045022100eefdd6cace70ee64d6a29bca5f52c338b2b3ecf6e6c7b222818c9bba60f094fb022053535e23a77afc7255c18ae8c6e6bf0f8b6e3f552d08519455714cbe59e489cf01210223078d2942df62c45621d209fab84ea9a7a23346201b7727b9b45a29c4e76f5effffffff0220a10700000000001976a9147821c0a3768aa9d1a37e16cf76002aef5373f1a888ac801a0600000000001976a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac00000000");
        }*/

        /*
        #[test]
        fn test_sign_segwit_ltc() {
            let unspents = vec![Utxo {
                tx_hash: "e868b66e75376add2154acb558cf45ff7b723f255e2aca794da1548eb945ba8b"
                    .to_string(),
                vout: 1,
                amount: 19850000,
                address: "MV3hqxhhcGxCdeLXpZKRCabtUApRXixgid".to_string(),
                script_pub_key: "76a91488d9931ea73d60eaf7e5671efc0552b912911f2a88ac".to_string(),
                derived_path: "1/0".to_string(),
                sequence: 0,
            }];
            let tx_input = BtcForkTxInput {
                to: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
                amount: 19800000,
                unspents,
                fee: 50000,
                change_address_index: 1u32,
                change_address: "".to_string(),
                network: "".to_string(),
                seg_wit: "".to_string(),
            };
            let coin_info = coin_info_from_param("LITECOIN", "MAINNET", "NONE", "").unwrap();

            let pair = Secp256k1PrivateKey::from_slice(
                &hex::decode("f3731f49d830c109e054522df01a9378383814af5b01a9cd150511f12db39e6e")
                    .unwrap(),
            )
            .unwrap();

            let change_addr =
                BtcForkAddress::from_str("MV3hqxhhcGxCdeLXpZKRCabtUApRXixgid").unwrap();
            let expected = tran
                .sign_transaction(&vec![pair], change_addr.script_pubkey())
                .unwrap();
            assert_eq!(expected.signature, "020000000001018bba45b98e54a14d79ca2a5e253f727bff45cf58b5ac5421dd6a37756eb668e801000000171600147b03478d2f7c984179084baa38f790ed1d37629bffffffff01c01f2e010000000017a91400aff21f24bc08af58e41e4186d8492a10b84f9e8702483045022100d0cc3d94c7b7b34fdcc2adc4fd3f735560407581afd6caa11c8d04b963a048a00220777d98e0122fe97206875f49556a401dfc449739ec30e44cb9ed9b92a0b3ff1b01210209c629c64829ec2e99703600ee86c7161a9ed13213e714726210274c29cf780900000000");
        }*/
    }
}
