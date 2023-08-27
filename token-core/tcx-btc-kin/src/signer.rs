use std::io::Write;
use tcx_chain::{Keystore, TransactionSigner};

use bitcoin::{
    EcdsaSighashType, OutPoint, PackedLockTime, SchnorrSighashType, Script, Sequence, Transaction,
    TxIn, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::Hash;

use super::Error;
use crate::Result;
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::serialize;
use bitcoin::psbt::Prevouts;
use bitcoin::schnorr::TapTweak;
use std::str::FromStr;

use crate::address::BtcKinAddress;
use crate::transaction::*;
use bitcoin::util::sighash::SighashCache;
use bitcoin_hashes::hash160;
use bitcoin_hashes::hex::FromHex as HashFromHex;
use bitcoin_hashes::hex::ToHex as HashToHex;
use byteorder::{BigEndian, WriteBytesExt};
use secp256k1::{Message, Secp256k1};
use tcx_chain::keystore::Error as KeystoreError;
use tcx_chain::Address;
use tcx_primitive::{Derive, PrivateKey, PublicKey, Secp256k1PrivateKey};

const MIN_TX_FEE: u64 = 546;

pub trait ScriptPubKeyComponent {
    fn address_script_like(target_addr: &str, pub_key: &bitcoin::PublicKey) -> Result<Script>;
    fn address_script_pub_key(target_addr: &str) -> Result<Script>;
}

pub struct TxSigner {
    tx: Transaction,
    private_keys: Vec<Secp256k1PrivateKey>,
    prevouts: Vec<TxOut>,
}

impl TxSigner {
    fn hash160(&self, input: &[u8]) -> hash160::Hash {
        hash160::Hash::hash(input)
    }
    fn sign_p2pkh_input(
        &mut self,
        sighash_cache: &mut SighashCache<&Transaction>,
        index: usize,
    ) -> Result<()> {
        let key = &self.private_keys[index];
        let prevout = &self.prevouts[index];

        let hash = sighash_cache.legacy_signature_hash(
            index,
            &prevout.script_pubkey,
            EcdsaSighashType::All.to_u32(),
        )?;
        let sig = key.sign(&hash)?;

        let sig = [sig, vec![1]].concat();

        self.tx.input[index].script_sig = Builder::new()
            .push_slice(&sig)
            .push_slice(&key.public_key().to_bytes())
            .into_script();

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh_input(
        &mut self,
        sighash_cache: &mut SighashCache<&Transaction>,
        index: usize,
    ) -> Result<()> {
        let prevout = &self.prevouts[index];
        let key = &self.private_keys[index];
        let pub_key = key.public_key();

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(
            self.hash160(&pub_key.to_compressed()),
        ));

        let hash = sighash_cache.segwit_signature_hash(
            index,
            &script.p2wpkh_script_code().expect("must be v0_p2wpkh"),
            prevout.value as u64,
            EcdsaSighashType::All,
        )?;
        let sig = key.sign(&hash)?;

        let tx_input = &mut self.tx.input[index];

        let sig = [sig, vec![1]].concat();

        tx_input.witness.push(sig);
        tx_input.witness.push(pub_key.to_bytes());
        tx_input.script_sig = Builder::new().push_slice(&script.to_bytes()).into_script();

        Ok(())
    }

    fn sign_p2wpkh_input(
        &mut self,
        sighash_cache: &mut SighashCache<&Transaction>,
        index: usize,
    ) -> Result<()> {
        let key = &self.private_keys[index];
        let prevout = &self.prevouts[index];

        let hash = sighash_cache.segwit_signature_hash(
            index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let sig = key.sign(&hash)?;

        let tx_input = &mut self.tx.input[index];

        let sig = [sig, vec![1]].concat();
        tx_input.witness.push(sig);
        tx_input.witness.push(key.public_key().to_bytes());

        Ok(())
    }

    fn sign_p2tr_input(
        &mut self,
        sighash_cache: &mut SighashCache<&Transaction>,
        index: usize,
    ) -> Result<()> {
        let key = &self.private_keys[index];
        let secp = Secp256k1::new();

        let key_pair =
            bitcoin::schnorr::UntweakedKeyPair::from_seckey_slice(&secp, &key.to_bytes())?
                .tap_tweak(&secp, None);

        let hash = sighash_cache.taproot_signature_hash(
            index,
            &Prevouts::All(&self.prevouts.clone()),
            None,
            None,
            SchnorrSighashType::All,
        )?;

        let msg = Message::from_slice(&hash[..])?;
        let sig = secp.sign_schnorr(&msg, &key_pair.to_inner());

        let tx_input = &mut self.tx.input[index];

        tx_input.witness.push(sig.as_ref());

        Ok(())
    }

    fn sign(&mut self) -> Result<()> {
        let cloned_tx = self.tx.clone();
        let mut sighash_cache = SighashCache::new(&cloned_tx);

        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh_input(&mut sighash_cache, idx)?;
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh_input(&mut sighash_cache, idx)?;
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh_input(&mut sighash_cache, idx)?;
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr_input(&mut sighash_cache, idx)?;
            }
        }

        Ok(())
    }
}

pub struct KinTransaction {
    inputs: Vec<Utxo>,
    amount: i64,
    fee: i64,
    to: Script,
    change_script: Script,
    op_return: Option<String>,
}

impl KinTransaction {
    fn tx_outs(&self) -> Result<Vec<TxOut>> {
        let mut total_amount = 0;

        for input in &self.inputs {
            total_amount += input.amount;
        }

        ensure!(self.amount >= MIN_TX_FEE as i64, "amount_less_than_minimum");

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

        if change_amount >= MIN_TX_FEE as i64 {
            tx_outs.push(TxOut {
                value: change_amount as u64,
                script_pubkey: self.change_script.clone(),
            });
        }

        if let Some(op_return) = &self.op_return {
            tx_outs.push(TxOut {
                value: 0,
                script_pubkey: Script::new_op_return(&hex::decode(op_return)?),
            });
        }

        Ok(tx_outs)
    }

    pub fn sign(
        &self,
        version: i32,
        private_keys: Vec<Secp256k1PrivateKey>,
    ) -> Result<BtcKinTxOutput> {
        let mut prevouts = vec![];
        let mut tx_inputs: Vec<TxIn> = vec![];

        for inp in self.inputs.iter() {
            prevouts.push(TxOut {
                value: inp.amount as u64,
                script_pubkey: BtcKinAddress::from_str(&inp.address)?.script_pubkey(),
            });

            tx_inputs.push(TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::hash_types::Txid::from_hex(&inp.tx_hash)?,
                    vout: inp.vout as u32,
                },
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            });
        }

        let tx_outs = self.tx_outs()?;

        let tx = Transaction {
            version,
            lock_time: PackedLockTime::ZERO,
            input: tx_inputs,
            output: tx_outs,
        };

        let mut singer = TxSigner {
            tx,
            private_keys,
            prevouts,
        };

        singer.sign()?;
        let tx = singer.tx;
        let tx_bytes = serialize(&tx);
        let tx_hash = tx.txid().to_hex();
        let wtx_hash = tx.wtxid().to_hex();

        Ok(BtcKinTxOutput {
            raw_tx: tx_bytes.to_hex(),
            wtx_hash,
            tx_hash,
        })
    }
}

impl TransactionSigner<BtcKinTxInput, BtcKinTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        symbol: &str,
        address: &str,
        tx: &BtcKinTxInput,
    ) -> Result<BtcKinTxOutput> {
        let account = self
            .account(symbol, address)
            .ok_or(KeystoreError::AccountNotFound)?;
        let coin_info = account.coin_info();

        if tx.inputs.len() == 0 {
            return Err(Error::InvalidInputCells.into());
        }

        let change_script = if let Some(change_address_index) = tx.change_address_index && self.determinable() {
            let dpk = account.deterministic_public_key()?;
            let pub_key = dpk
                .derive(format!("1/{}", change_address_index).as_str())?
                .public_key();
            let change_address = BtcKinAddress::from_public_key(&pub_key, &coin_info)?;

            BtcKinAddress::from_str(&change_address)?.script_pubkey()
        } else {
            BtcKinAddress::from_str(&tx.inputs[0].address)?.script_pubkey()
        };

        let to = BtcKinAddress::from_str(&tx.to)?.script_pubkey();

        let mut sks = vec![];
        for x in tx.inputs.iter() {
            if x.derived_path.len() > 0 && self.determinable() {
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

        let version = if coin_info.seg_wit != "NONE" { 2 } else { 1 };

        let kin_tx = KinTransaction {
            inputs: tx.inputs.clone(),
            amount: tx.amount,
            fee: tx.fee,
            to,
            change_script,
            op_return: tx.op_return.clone(),
        };

        kin_tx.sign(version as i32, sks)
    }
}

impl TransactionSigner<OmniTxInput, BtcKinTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        _: &str,
        address: &str,
        tx: &OmniTxInput,
    ) -> Result<BtcKinTxOutput> {
        /*
        OmniLayer Protocol marker(0x6f6d6e69) + 2bytes transaction version (0)
         + 2bytes transaction type(0: simple send)
         + 4bytes  Property type (31 is USDT)
        byte[] OMNI_DATA_PREFIX = NumericUtil.hexToBytes("0x6f6d6e69000000000000001f");
        */
        let create_omni_op_return = || {
            let mut wtr = Vec::new();
            wtr.write(&hex::decode("6f6d6e6900000000").unwrap())
                .unwrap();
            wtr.write_u32::<BigEndian>(tx.property_id as u32).unwrap();
            wtr.write_u64::<BigEndian>(tx.amount as u64).unwrap();
            wtr.to_hex()
        };

        let btc_tx = BtcKinTxInput {
            inputs: tx.inputs.clone(),
            amount: MIN_TX_FEE as i64,
            to: tx.to.clone(),
            fee: tx.fee,
            change_address_index: None,
            op_return: Some(create_omni_op_return()),
        };

        self.sign_transaction("BITCOIN", address, &btc_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::address::BtcKinAddress;
    use tcx_chain::Metadata;
    use tcx_chain::{Keystore, TransactionSigner};
    use tcx_constants::coin_info::coin_info_from_param;
    use tcx_constants::{TEST_MNEMONIC, TEST_PASSWORD, TEST_WIF};
    use tcx_primitive::Secp256k1PrivateKey;

    fn setup(keystore: &mut Keystore) {
        let need_setup = [
            ("BITCOIN", "MAINNET", "NONE"),
            ("BITCOIN", "MAINNET", "P2WPKH"),
            ("BITCOIN", "MAINNET", "SEGWIT"),
            ("BITCOIN", "MAINNET", "P2TR"),
            ("BITCOIN", "TESTNET", "NONE"),
            ("BITCOIN", "TESTNET", "P2WPKH"),
            ("BITCOIN", "TESTNET", "SEGWIT"),
            ("BITCOIN", "TESTNET", "P2TR"),
            ("LITECOIN", "MAINNET", "NONE"),
            ("LITECOIN", "MAINNET", "P2WPKH"),
            ("LITECOIN", "TESTNET", "NONE"),
            ("LITECOIN", "TESTNET", "P2WPKH"),
        ];

        for i in need_setup {
            let coin_info = coin_info_from_param(i.0, i.1, i.2, "").unwrap();
            let account = &keystore.derive_coin::<BtcKinAddress>(&coin_info).unwrap();
            println!("account {:?}", account);
        }
    }

    fn hex_keystore(hex: &str) -> Keystore {
        println!("hex {}", hex);
        let mut keystore = Keystore::from_private_key(hex, TEST_PASSWORD, Metadata::default());
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        setup(&mut keystore);
        keystore
    }

    fn wif_keystore(wif: &str) -> Keystore {
        let hex = Secp256k1PrivateKey::from_wif(TEST_WIF)
            .unwrap()
            .to_bytes()
            .to_hex();

        hex_keystore(&hex)
    }

    fn hd_keystore(mnemonic: &str) -> Keystore {
        let mut keystore =
            Keystore::from_mnemonic(mnemonic, TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(TEST_PASSWORD).unwrap();
        setup(&mut keystore);
        keystore
    }

    fn sample_private_key_keystore() -> Keystore {
        wif_keystore(TEST_WIF)
    }

    fn sample_hd_keystore() -> Keystore {
        hd_keystore(TEST_MNEMONIC)
    }

    mod kin {
        use super::*;

        #[test]
        fn test_sign_less_than_dust() {
            let mut ks = sample_private_key_keystore();

            let inputs = vec![Utxo {
                tx_hash: "e112b1215813c8888b31a80d215169809f7901359c0f4bf7e7374174ab2a64f4"
                    .to_string(),
                vout: 0,
                amount: 65000000,
                address: "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6".to_string(),
                derived_path: "".to_string(),
            }];

            let tx_input = BtcKinTxInput {
                to: "mxCVgJtD2jSMv2diQVJQAwwq7Cg2wbwpmG".to_string(),
                amount: MIN_TX_FEE as i64 - 1,
                inputs: inputs.clone(),
                fee: 1000,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual =
                ks.sign_transaction("BITCOIN", "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6", &tx_input);
            assert_eq!(
                actual.err().unwrap().to_string(),
                "amount_less_than_minimum"
            );
        }
    }

    mod omni {
        use super::*;

        #[test]
        fn test_sign_with_hd_on_testnet() {
            let mut ks = sample_hd_keystore();
            let inputs = vec![Utxo {
                tx_hash: "0dd195c815c5086c5995f43a0c67d28344ae5fa130739a5e03ef40fea54f2031"
                    .to_string(),
                vout: 0,
                amount: 14824854,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                derived_path: "0/0".to_string(),
            }];

            let tx_input = OmniTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 10000000000,
                inputs,
                fee: 4000,
                property_id: 31,
            };

            let actual = ks
                .sign_transaction("OMNI", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_eq!(actual.raw_tx, "010000000131204fa5fe40ef035e9a7330a15fae4483d2670c3af495596c08c515c895d10d000000006a4730440220138f0bb42eda662c061e285e4999ff8297fedaedcdbcb5f7b5166234a685d3560220116e7b55d242f384cf02891cbd3eb602935177128e62a1efe670c0bf063a90000121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0322020000000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088acd423e200000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac0000000000000000166a146f6d6e69000000000000001f00000002540be40000000000");
        }

        #[test]
        fn test_sign_with_hd_p2shp2wpkh_on_testnet() {
            let mut ks = sample_hd_keystore();
            let inputs = vec![Utxo {
                tx_hash: "9baf6fd0e560f9f199f4879c23cb73b9c4affb54a1cfdbacb85687efa89f4c78"
                    .to_string(),
                vout: 1,
                amount: 21863396,
                address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                derived_path: "0/0".to_string(),
            }];

            let tx_input = OmniTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 10000000000,
                inputs,
                fee: 4000,
                property_id: 31,
            };

            let actual = ks
                .sign_transaction("OMNI", "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", &tx_input)
                .unwrap();
            assert_eq!(actual.raw_tx, "02000000000101784c9fa8ef8756b8acdbcfa154fbafc4b973cb239c87f499f1f960e5d06faf9b0100000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff0322020000000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac228a4d010000000017a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f78759870000000000000000166a146f6d6e69000000000000001f00000002540be4000247304402207e9c6d232084c9a0bcfa1f36184e6b044912e88630ebe624679642a99692529102202318c4c3a42d5656d300a42dc7796c5e0a6e9d1fb13465279fbe58bcd13345460121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc00000000");
        }
    }

    mod btc {
        use super::*;

        #[test]
        fn test_sign_with_multi_payment_on_testnet() {
            let mut ks = sample_hd_keystore();

            let inputs = vec![
                Utxo {
                    tx_hash: "aea080afe2cdeb23f0d9f546d386329addda5a6fdc521e02d74d5a4e4461dc4a"
                        .to_string(),
                    vout: 0,
                    amount: 20000,
                    address: "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "aea080afe2cdeb23f0d9f546d386329addda5a6fdc521e02d74d5a4e4461dc4a"
                        .to_string(),
                    vout: 1,
                    amount: 283000,
                    address: "tb1pjvp6z9shfhfpafrnwen9j452cf8tdwpgc0hfnzvz62aqwr4qv92sg7qj9r"
                        .to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "13dca25cc94c015067761f5cecf48dfb3afcaea78abeb28ce1b585bf4980cc12"
                        .to_string(),
                    vout: 0,
                    amount: 100000,
                    address: "tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "0122f46a161ded9805d95930549b2e4d93a765ef3dd5f10052c68c9270659e72"
                        .to_string(),
                    vout: 1,
                    amount: 100000,
                    address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "d8929d60667d2a717abd833828a899795c45c843352b3552322fcd75447226a1"
                        .to_string(),
                    vout: 1,
                    amount: 100000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
            ];

            let tx_input = BtcKinTxInput {
                inputs: inputs.clone(),
                to: "tb1pxcrec4q8tzj34phw470pwe5dfkz58k93kljklck6pxpv8yx9v40q66tmr7".to_string(),
                amount: 40000,
                fee: 40000,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual = ks
                .sign_transaction("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            /*    assert_eq!(actual.raw_tx, "020000000001054adc61444e5a4dd7021e52dc6f5adadd9a3286d346f5d9f023ebcde2af80a0ae0000000000ffffffff4adc61444e5a4dd7021e52dc6f5adadd9a3286d346f5d9f023ebcde2af80a0ae0100000000ffffffff12cc8049bf85b5e18cb2be8aa7aefc3afb8df4ec5c1f766750014cc95ca2dc130000000000ffffffff729e6570928cc65200f1d53def65a7934d2e9b543059d90598ed1d166af422010100000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffffa126724475cd2f3252352b3543c8455c7999a8283883bd7a712a7d66609d92d8010000006b483045022100ca32abc7b180c84cf76907e4e1e0c3f4c0d6e64de23b0708647ac6fee1c04c5b02206e7412a712424eb9406f18e00a42e0dffbfb5901932d1ef97843d9273865550e0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02409c00000000000022512036079c540758a51a86eeaf9e17668d4d8543d8b1b7e56fe2da0982c390c5655ef8fa0700000000002251209303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea0615501400391589e6eb0e8132b8ceb6a6ad4467eee7b04963111106aaf9449862dfba8f0492b36da66da7a16efb109d2e184c907979522adbcafe9abddd132028c22021001408b6246f16124e3e21f68b8675c00a8422fa617ae6dce0e38a2a1d75f2b285db9fbe0ea43a9f92b06c0e4b4ad631e5a3102f054c0b497207f632128c0222a883b02473044022022c2feaa4a225496fc6789c969fb776da7378f44c588ad812a7e1227ebe69b6302204fc7bf5107c6d02021fe4833629bc7ab71cefe354026ebd0d9c0da7d4f335f94012102e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c002483045022100dec4d3fd189b532ef04f41f68319ff7dc6a7f2351a0a8f98cb7f1ec1f6d71c7a02205e507162669b642fdb480a6c496abbae5f798bce4fd42cc390aa58e3847a1b910121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc0000000000" );
               assert_eq!(
                   actual.tx_hash,
                   "2bdcfa88d5f48954e98018da33aaf11a4951b4167ba8121bc787880890dee5f0"

               );

            */
        }

        #[test]
        fn test_sign_with_private_key_on_testnet() {
            let mut ks = sample_private_key_keystore();

            let inputs = vec![Utxo {
                tx_hash: "e112b1215813c8888b31a80d215169809f7901359c0f4bf7e7374174ab2a64f4"
                    .to_string(),
                vout: 0,
                amount: 65000000,
                address: "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6".to_string(),
                derived_path: "".to_string(),
            }];

            let tx_input = BtcKinTxInput {
                to: "mxCVgJtD2jSMv2diQVJQAwwq7Cg2wbwpmG".to_string(),
                amount: MIN_TX_FEE as i64 - 1,
                inputs: inputs.clone(),
                fee: 1000,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual =
                ks.sign_transaction("BITCOIN", "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6", &tx_input);
            assert_eq!(
                actual.err().unwrap().to_string(),
                "amount_less_than_minimum"
            );

            let tx_input = BtcKinTxInput {
                inputs: inputs.clone(),
                to: "mxCVgJtD2jSMv2diQVJQAwwq7Cg2wbwpmG".to_string(),
                amount: 63999000,
                fee: 65000000 - 63999000 - MIN_TX_FEE as i64 + 1,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual = ks
                .sign_transaction("BITCOIN", "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6", &tx_input)
                .unwrap();

            assert_eq!(actual.raw_tx, "0100000001f4642aab744137e7f74b0f9c3501799f806951210da8318b88c8135821b112e1000000006b4830450221009b4a952af51fa057b8e5fb2eb114d0396a0fcbd2912d49c557bb11fc4caa87440220664202cffe79927aaef08aef9a07a60d9cf3f07599b5333d2b31ff2a701974e6012102506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aabaffffffff01188cd003000000001976a914b6fc6ecf55a41b240fd26aaed696624009818d9988ac00000000");

            let tx_input = BtcKinTxInput {
                to: "mxCVgJtD2jSMv2diQVJQAwwq7Cg2wbwpmG".to_string(),
                amount: 60000000,
                inputs: inputs.clone(),
                fee: 1000000,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual = ks
                .sign_transaction("BITCOIN", "n2ZNV88uQbede7C5M5jzi6SyG4GVuPpng6", &tx_input)
                .unwrap();
            assert_eq!(actual.raw_tx, "0100000001f4642aab744137e7f74b0f9c3501799f806951210da8318b88c8135821b112e1000000006b483045022100a2d7e684e61df275c35055952a37d0411964caf653172d947475153444ee1c20022038e1219322562864af183c9d4a9a376968b00efb8943ea84475799a23f412a3c012102506bc1dc099358e5137292f4efdd57e400f29ba5132aa5d12b18dac1c1f6aabaffffffff0200879303000000001976a914b6fc6ecf55a41b240fd26aaed696624009818d9988ac00093d00000000001976a914e6cfaab9a59ba187f0a45db0b169c21bb48f09b388ac00000000");
        }

        #[test]
        fn test_sign_with_hd_on_testnet() {
            let mut ks = sample_hd_keystore();

            let inputs = vec![
                Utxo {
                    tx_hash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                        .to_string(),
                    vout: 0,
                    amount: 200000000,
                    address: "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC".to_string(),
                    derived_path: "0/22".to_string(),
                },
                Utxo {
                    tx_hash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                        .to_string(),
                    vout: 1,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                        .to_string(),
                    vout: 0,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                        .to_string(),
                    vout: 1,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
            ];

            let tx_input = BtcKinTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 799988000,
                inputs: inputs.clone(),
                fee: 12000,
                change_address_index: Some(53u32),
                op_return: None,
            };

            let actual = ks
                .sign_transaction("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_eq!(actual.raw_tx, "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c610f77f71cc8afcfbd46df8e3d564fb8fb0f2c041bdf0869512c461901a8ad802206b92460cccbcb2a525877db1b4b7530d9b85e135ce88424d1f5f345dc65b881401210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100dce4a4c3d79bf9392832f68da3cd2daf85ac7fa851402ecc9aaac69b8761941d02201e1fd6601812ea9e39c6df0030cb754d4c578ff48bc9db6072ba5207a4ebc2b60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100e1802d80d72f5f3be624df3ab668692777188a9255c58067840e4b73a5a61a99022025b23942deb21f5d1959aae85421299ecc9efefb250dbacb46a4130abd538d730121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a47304402207b82a62ed0d35c9878e6a7946d04679c8a17a8dd0a856b5cc14928fe1e9b554a0220411dd1a61f8ac2a8d7564de84e2c8a2c2583986bd71ac316ade480b8d0b4fffd0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0120d9ae2f000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac00000000");

            let tx_input = BtcKinTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 750000000,
                inputs,
                fee: 502130,
                change_address_index: Some(53u32),
                op_return: None,
            };

            //contains change
            let actual = ks
                .sign_transaction("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();

            //see https://mempool.space/testnet/tx/3aa6ed94e29c01b96fe3a20c30825d161f421d5e2358eb1ceade43de533e1977#vin=0
            assert_eq!(
                actual.tx_hash,
                "3aa6ed94e29c01b96fe3a20c30825d161f421d5e2358eb1ceade43de533e1977"
            );
            assert_eq!(actual.raw_tx, "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006b483045022100c4f39ce7f2448ab8e7154a7b7ce82edd034e3f33e1f917ca43e4aff822ba804c02206dd146d1772a45bb5e51abb081d066114e78bcb504671f61c5a301a647a494ac01210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100d235afda9a56aaa4cbe05df712202e6b1a45aab7a0c83540d3053133f15acc5602201b0e144bec3a02a5c556596040b0be81b0202c19b163bb537b8d965afd61403a0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100dd8f1e20116f96a3400f55e0c637a0ad21ae47ff92d83ffb0c3d324c684a54be0220064b0a6d316154ef07a69bd82de3a052e43c3c6bb0e55e4de4de939b093e1a3a0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006a473044022048d8cb0f1480174b3b9186cc6fe410db765f1f9d3ce036b0d4dee0eb19aa3641022073de4bb2b00a0533e9c8f3e074c655e0695c8b223233ddecf3c99a84351d50a60121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff028017b42c000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac0e47f302000000001976a91412967cdd9ceb72bbdbb7e5db85e2dbc6d6c3ab1a88ac00000000");
        }

        #[test]
        fn test_sign_op_return_with_hd_on_testnet() {
            let mut ks = sample_hd_keystore();

            let unspent = vec![
                Utxo {
                    tx_hash: "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a"
                        .to_string(),
                    vout: 0,
                    amount: 200000000,
                    address: "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC".to_string(),
                    derived_path: "0/22".to_string(),
                },
                Utxo {
                    tx_hash: "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531"
                        .to_string(),
                    vout: 1,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9"
                        .to_string(),
                    vout: 0,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9"
                        .to_string(),
                    vout: 1,
                    amount: 200000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
            ];

            let tx_input = BtcKinTxInput {
                to: "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3".to_string(),
                amount: 799988000,
                inputs: unspent,
                fee: 12000,
                change_address_index: Some(53u32),
                op_return: Some("1234".to_string()),
            };

            let actual = ks
                .sign_transaction("BITCOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();

            assert_eq!(actual.raw_tx, "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000006a473044022018bdc26d15552ddda446a07212c1cffcc259a51830a347b379c842d4823f76330220239a54e93e315778adcb2d96eb32688594764c471ceb28c811a4300916a875a901210312a0cb31ff52c480c049da26d0aaa600f47e9deee53d02fc2b0e9acf3c20fbdfffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000006b483045022100ee3f5a4acbf595ccdeae6c7f31ed51c3595c5814b1098345db94b85fd4e681030220412a0f8da13a9df4447018637b0fe31d11a795b2c1f8174128d2fd0608269f9b0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000006b483045022100f4be2b77fe1cb152e2c1868cedd4e3cf8f6af5b73b10fb4ba8ea95b279f10a37022023227ff8efde2a1dd72e4363fb75e3da80ae6c4f6c66cdf66e55b835c54549640121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000006b483045022100a2561e13c430c8d136c13de0f34913e9c5c1d26f8b577a2fe206b9285538020f02204af7501eab7c562f868e5369fddc93f654fa80227166104a4ac11cf43cfe2caf0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff0220d9ae2f000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac0000000000000000046a02123400000000")
        }

        #[test]
        fn test_sign_p2shwpkh_on_testnet() {
            let mut ks = sample_hd_keystore();

            let unspent = vec![
                Utxo {
                    tx_hash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                        .to_string(),
                    vout: 0,
                    amount: 50000,
                    address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                        .to_string(),
                    vout: 0,
                    amount: 50000,
                    address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                    derived_path: "0/1".to_string(),
                },
            ];

            let tx_input = BtcKinTxInput {
                to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
                amount: 88000,
                inputs: unspent.clone(),
                fee: 12000,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual = ks
                .sign_transaction("BITCOIN", "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", &tx_input)
                .unwrap();

            assert_eq!(actual.raw_tx, "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff01c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e870247304402205fd9dea5df0db5cc7b1d4b969f63b4526fb00fd5563ab91012cb511744a53d570220784abfe099a2b063b1cfc1f145fef2ffcb100b0891514fa164d357f0ef7ca6bb0121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02483045022100b0246c12428dbf863fcc9060ab6fc46dc2135adaa6cf8117de49f9acecaccf6c022059377d05c9cab24b7dec14242ea3206cc1f464d5ff9904dca515fc71766507cd012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000");

            let tx_input = BtcKinTxInput {
                to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
                amount: 80000,
                inputs: unspent.clone(),
                fee: 10000,
                change_address_index: Some(0u32),
                op_return: None,
            };

            let actual = ks
                .sign_transaction("BITCOIN", "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", &tx_input)
                .unwrap();

            assert_eq!(actual.raw_tx, "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff02803801000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e87102700000000000017a914755fba51b5c443b9f16b1f86665dec10dd7a25c58702483045022100f0c66cd322e50f992ad34448fb3bf823066e5ffaa8e840a901058a863a4d950c02206cdafb1ad1ef4d938122b106069d8b435387e4d55711f50a46a8d91d9f674c550121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc02483045022100cfe92e4ad4fbfc13be20afc6f37429e26426257d015b409d28c260544e581b2c022028412816d1fef11093b474c2c662a25a4062f4e37d06ce66207863de98814a07012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000");
        }

        #[test]
        fn test_sign_segwit_with_op_return_on_testnet() {
            let mut ks = sample_hd_keystore();

            let unspent = vec![
                Utxo {
                    tx_hash: "c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f"
                        .to_string(),
                    vout: 0,
                    amount: 50000,
                    address: "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74"
                        .to_string(),
                    vout: 0,
                    amount: 50000,
                    address: "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf".to_string(),
                    derived_path: "0/1".to_string(),
                },
            ];

            let tx_input = BtcKinTxInput {
                to: "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp".to_string(),
                amount: 88000,
                inputs: unspent.clone(),
                fee: 12000,
                change_address_index: Some(0u32),
                op_return: Some("1234".to_string()),
            };

            let actual = ks
                .sign_transaction("BITCOIN", "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", &tx_input)
                .unwrap();

            assert_eq!(actual.raw_tx, "020000000001027f717276057e6012afa99385c18cc692397a666560520577679bf38c08b5cec20000000017160014654fbb08267f3d50d715a8f1abb55979b160dd5bffffffff74cdd54bc48333e1d2f108460284d137c39b6c417d9ff55a572a9550d428d69a00000000171600149d66aa6399de69d5c5ae19f9098047760251a854ffffffff02c05701000000000017a914b710f6e5049eaf0404c2f02f091dd5bb79fa135e870000000000000000046a021234024730440220527c098c320c54ac56445b757a76833f7a47229fa0fe2b179f55bd718822695e022060f48b05c46f8335266eade0fe503448ff4222efc7e84ef86a25abffbe02ead20121031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc024730440220551ab42b94841b43e6118a6adb39a561f138ae9ee8d2c00ffa3886839afe66d2022046686666245b94b7272d7cbd17a6f20639532ddefafe0572ecc28dcb246d33f8012103a241c8d13dd5c92475652c43bf56580fbf9f1e8bc0aa0132ddc8443c03062bb900000000");
        }
    }

    mod ltc {
        use super::*;

        #[test]
        fn test_sign_with_hd_on_testnet() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let inputs = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                derived_path: "0/0".to_string(),
            }];
            let tx_input = BtcKinTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                inputs,
                fee: 5902,
                change_address_index: None,
                op_return: None,
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let actual = keystore
                .sign_transaction("LITECOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_eq!(
                actual.tx_hash,
                "e15054b5a45400796fe3f8605c7dd84ff6ec7e08f444969ba24fa1c285d10df9"
            );
            assert_eq!(actual.raw_tx, "010000000101a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006b48304502210090beb741ec38b0931a457c40086ba183c0cc85542bce5e5811a2377e954a113b022029a37ba9ccfe57fc77f639c7599d4fcf35f2fb921a610967a88dba0a800ee9ae0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02a0860100000000001976a914461bf9360ec1bc9fe438df19ef36c7c2bb26ef8288ac92a40d00000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac00000000");
        }

        #[test]
        fn test_sign_multi_utxo_with_hd_on_testnet() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let inputs = vec![
                Utxo {
                    tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
                Utxo {
                    tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a100"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                    derived_path: "0/0".to_string(),
                },
            ];
            let tx_input = BtcKinTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 1100000,
                inputs,
                fee: 5902,
                change_address_index: Some(1u32),
                op_return: None,
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let actual = keystore
                .sign_transaction("LITECOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_eq!(
                actual.tx_hash,
                "c8d5b9bda8a43a8cc04b1271c2fd5d92d45ed00b2a64193f531ee0f05f3afe96"
            );

            assert_eq!(actual.raw_tx, "010000000201a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006b483045022100a49798664e490075f9d111c6b6e8541781a5a88df1b95eb910dd307298ead4e802203adb4a21f2e680e1d05f6346ec25b1077f60e58c6289606cc9dad15698b5368d0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff00a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006a473044022100c7e2dba307022d45067e7b3eceb2b288f49037f43c8bac271ccc831f250b9438021f14103613f41f6d6811f70359077ae96dc2055fcb9dd5aff21469e1fb51a9870121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02e0c81000000000001976a914461bf9360ec1bc9fe438df19ef36c7c2bb26ef8288ac92a40d00000000001976a9143770c8c6671d27e2a9f4502d74932bf740c1ff8688ac00000000");
        }

        #[test]
        fn test_wrong_derived_path() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let inputs = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                derived_path: "0/1".to_string(),
            }];
            let tx_input = BtcKinTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                inputs,
                fee: 5902,
                change_address_index: None,
                op_return: None,
            };

            let mut keystore = Keystore::from_json(keystore_json).unwrap();
            let _ = keystore.unlock_by_password("imtoken1");
            let actual = keystore
                .sign_transaction("LITECOIN", "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN", &tx_input)
                .unwrap();
            assert_ne!(
                actual.tx_hash,
                "f90dd185c2a14fa29b9644f4087eecf64fd87d5c60f8e36f790054a4b55450e1"
            );
            assert_ne!(actual.raw_tx, "010000000101a1d4a6b051e732341c0101a62488051bb5bf969d1f15324bbf6a1d2035c957000000006b48304502210090beb741ec38b0931a457c40086ba183c0cc85542bce5e5811a2377e954a113b022029a37ba9ccfe57fc77f639c7599d4fcf35f2fb921a610967a88dba0a800ee9ae0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4effffffff02a0860100000000001976a914461bf9360ec1bc9fe438df19ef36c7c2bb26ef8288ac92a40d00000000001976a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac00000000");
        }

        #[test]
        fn test_invalid_derived_path() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let inputs = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN".to_string(),
                derived_path: "hello//ggg".to_string(),
            }];
            let tx_input = BtcKinTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                inputs,
                fee: 5902,
                change_address_index: None,
                op_return: None,
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
        fn test_sign_invalid_unspent_address() {
            let keystore_json = r#"
        {"id":"ae45d424-31d8-49f7-a601-1272b40c566d","version":11000,"keyHash":"512115eca3ae86646aeb06861d551e403b543509","crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"588233984e9576f058bd7bae018eaa38"},"ciphertext":"8a5451c57fed478c7d45f5391659a6fb5fc85a347f1f7aaead450ad4ef4fe434d042d57aa990d850165293609aa746c715c805b236c3d54d86e7dea7d938ce55fcb2684e0eb7e0e6cc7d","kdf":"pbkdf2","kdfparams":{"c":1024,"prf":"hmac-sha256","dklen":32,"salt":"ee656af962155e4e6e763b0883ed0d8cc37c2fa21a7ef01b1d3b18f352f74c69"},"mac":"a661aa444869aac9ea33f066676c6bfb49d079ab986d0ee755f8a1747b2b7f17"},"activeAccounts":[{"address":"mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN","derivationPath":"m/44'/1'/0'/0/0","curve":"SECP256k1","coin":"LITECOIN","network":"TESTNET","segWit":"NONE","extPubKey":"036c2b38ad8000000023332f38a77023d3c1a450499c8aeb3db2e666aa2cc6fff7db6797c5d2aef8fc036663443d71127b332c68cd6bffb6c2b5eb4dc6861404ed055dc36a25b8c18020"}],"imTokenMeta":{"name":"LTC-Wallet-1","passwordHint":"","timestamp":1576561805,"source":"MNEMONIC"}}
        "#;
            let inputs = vec![Utxo {
                tx_hash: "57c935201d6abf4b32151f9d96bfb51b058824a601011c3432e751b0a6d4a101"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "address_invalid".to_string(),
                derived_path: "0/0".to_string(),
            }];
            let tx_input = BtcKinTxInput {
                to: "mmuf77YiGckWgfvd32viaj7EKfrUN1FdAz".to_string(),
                amount: 100000,
                inputs,
                fee: 5902,
                change_address_index: None,
                op_return: None,
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
        fn test_sign_amount_great_than_inputs() {
            // amount great than inputs
            let inputs = vec![Utxo {
                tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                    .to_string(),
                vout: 0,
                amount: 1000000,
                address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                derived_path: "0/0".to_string(),
            }];
            let coin_info = coin_info_from_param("LITECOIN", "TESTNET", "NONE", "").unwrap();
            let tx_input = BtcKinTxInput {
                to: "mrU9pEmAx26HcbKVrABvgL7AwA5fjNFoDc".to_string(),
                amount: 1500000,
                inputs,
                fee: 100000,
                change_address_index: None,
                op_return: None,
            };

            let mut ks = wif_keystore("cSBnVM4xvxarwGQuAfQFwqDg9k5tErHUHzgWsEfD4zdwUasvqRVY");
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
            keystore.derive_coin::<BtcKinAddress>(&coin_info);

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

        #[test]
        fn test_sign_invalid_address() {
            let chain_types = vec!["BITCOINCASH", "LITECOIN"];
            for chain_type in chain_types {
                let inputs = vec![Utxo {
                    tx_hash: "a477af6b2667c29670467e4e0728b685ee07b240235771862318e29ddbe58458"
                        .to_string(),
                    vout: 0,
                    amount: 1000000,
                    address: "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1".to_string(),
                    derived_path: "0/0".to_string(),
                }];
                let tx_input = BtcKinTxInput {
                    to: "address_invalid".to_string(),
                    amount: 500000,
                    inputs,
                    fee: 100000,
                    change_address_index: None,
                    op_return: None,
                };

                let mut ks = wif_keystore("mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1");

                let ret = ks.sign_transaction(
                    "LITECOIN",
                    "mszYqVnqKoQx4jcTdJXxwKAissE3Jbrrc1",
                    &tx_input,
                );
                assert!(ret.is_err());
            }
        }

        #[test]
        fn test_sign_segwit() {
            let inputs = vec![Utxo {
                tx_hash: "e868b66e75376add2154acb558cf45ff7b723f255e2aca794da1548eb945ba8b"
                    .to_string(),
                vout: 1,
                amount: 19850000,
                address: "MV3hqxhhcGxCdeLXpZKRCabtUApRXixgid".to_string(),
                derived_path: "1/0".to_string(),
            }];
            let tx_input = BtcKinTxInput {
                to: "M7xo1Mi1gULZSwgvu7VVEvrwMRqngmFkVd".to_string(),
                amount: 19800000,
                inputs,
                fee: 50000,
                change_address_index: None,
                op_return: None,
            };
            let mut ks =
                hex_keystore("f3731f49d830c109e054522df01a9378383814af5b01a9cd150511f12db39e6e");

            let actual = ks
                .sign_transaction("LITECOIN", "MV3hqxhhcGxCdeLXpZKRCabtUApRXixgid", &tx_input)
                .unwrap();
            assert_eq!(actual.raw_tx, "020000000001018bba45b98e54a14d79ca2a5e253f727bff45cf58b5ac5421dd6a37756eb668e801000000171600147b03478d2f7c984179084baa38f790ed1d37629bffffffff01c01f2e010000000017a91400aff21f24bc08af58e41e4186d8492a10b84f9e8702483045022100d0cc3d94c7b7b34fdcc2adc4fd3f735560407581afd6caa11c8d04b963a048a00220777d98e0122fe97206875f49556a401dfc449739ec30e44cb9ed9b92a0b3ff1b01210209c629c64829ec2e99703600ee86c7161a9ed13213e714726210274c29cf780900000000");
        }
    }
}
