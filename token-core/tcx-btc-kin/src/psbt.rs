use crate::bch_sighash::BitcoinCashSighash;
use crate::sighash::TxSignatureHasher;
use crate::transaction::{PsbtInput, PsbtOutput, PsbtsInput, PsbtsOutput};
use crate::{Error, Result, BITCOINCASH};
use bitcoin::blockdata::script::Builder;
use bitcoin::consensus::{Decodable, Encodable};
use bitcoin::psbt::{Prevouts, Psbt};
use bitcoin::schnorr::TapTweak;
use bitcoin::util::sighash::SighashCache;
use bitcoin::util::taproot::TapLeafHash;
use bitcoin::{
    EcdsaSig, EcdsaSighashType, SchnorrSig, SchnorrSighashType, Script, TxOut, WPubkeyHash, Witness,
};
use bitcoin_hashes::{hash160, Hash};
use secp256k1::ecdsa::Signature;
use secp256k1::Message;
use std::collections::BTreeMap;
use std::io::Cursor;
use tcx_common::{FromHex, ToHex};
use tcx_constants::CurveType;
use tcx_keystore::Keystore;
use tcx_primitive::{PrivateKey, Secp256k1PrivateKey, SECP256K1_ENGINE};

pub struct PsbtSigner<'a> {
    psbt: &'a mut Psbt,
    keystore: &'a mut Keystore,
    derivation_path: String,
    auto_finalize: bool,

    prevouts: Vec<TxOut>,
    sighash_cache: Box<dyn TxSignatureHasher>,
}

impl<'a> PsbtSigner<'a> {
    pub fn new(
        psbt: &'a mut Psbt,
        keystore: &'a mut Keystore,
        chain_type: &str,
        derivation_path: &str,
        auto_finalize: bool,
    ) -> Self {
        let unsigned_tx = psbt.unsigned_tx.clone();

        let sighash_cache: Box<dyn TxSignatureHasher> = if chain_type == BITCOINCASH {
            Box::new(BitcoinCashSighash::new(unsigned_tx, 0x40))
        } else {
            Box::new(SighashCache::new(Box::new(unsigned_tx)))
        };

        PsbtSigner {
            psbt,
            keystore,
            derivation_path: derivation_path.to_string(),
            auto_finalize,

            sighash_cache,
            prevouts: Vec::new(),
        }
    }

    fn hash160(input: &[u8]) -> hash160::Hash {
        Hash::hash(input)
    }

    fn sign_ecdsa(data: &[u8], key: &Secp256k1PrivateKey) -> Result<Signature> {
        let msg = Message::from_slice(data)?;
        let sig = SECP256K1_ENGINE.sign_ecdsa(&msg, &key.0.inner);
        Ok(sig)
    }

    fn prevouts(&self) -> Result<Vec<TxOut>> {
        let len = self.psbt.inputs.len();
        let mut utxos = Vec::with_capacity(len);

        for i in 0..len {
            let input = &self.psbt.inputs[i];
            let utxo = if let Some(witness_utxo) = &input.witness_utxo {
                witness_utxo
            } else if let Some(non_witness_utxo) = &input.non_witness_utxo {
                let vout = self.psbt.unsigned_tx.input[i].previous_output.vout;
                &non_witness_utxo.output[vout as usize]
            } else {
                return Err(Error::InvalidUtxo.into());
            };
            utxos.push(utxo.clone());
        }

        Ok(utxos)
    }

    fn get_private_key(&mut self, index: usize, is_p2tr: bool) -> Result<Secp256k1PrivateKey> {
        let input = &self.psbt.inputs[index];
        let mut path = if !self.derivation_path.is_empty() {
            format!("{}/0/0", self.derivation_path)
        } else {
            "".to_string()
        };

        if is_p2tr {
            let tap_bip32_derivation = input.tap_key_origins.first_key_value();

            if let Some((_, key_source)) = tap_bip32_derivation {
                path = key_source.1 .1.to_string();
            }
        } else {
            let bip32_derivations = input.bip32_derivation.first_key_value();

            if let Some((_, key_source)) = bip32_derivations {
                path = key_source.1.to_string();
            }
        }

        Ok(self
            .keystore
            .get_private_key(CurveType::SECP256k1, &path)?
            .as_secp256k1()?
            .clone())
    }

    fn finalize_p2wpkh(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();
            let mut witness = Witness::new();

            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness)
        }
    }

    fn finalize_p2pkh(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();

            input.final_script_sig = Some(
                Builder::new()
                    .push_slice(&sig.1.to_vec())
                    .push_slice(&sig.0.to_bytes())
                    .into_script(),
            );
        }
    }

    fn finalize_p2sh_nested_p2wpkh(&mut self, index: usize) {
        let mut input = &mut self.psbt.inputs[index];

        if !input.partial_sigs.is_empty() {
            let sig = input.partial_sigs.first_key_value().unwrap();

            let script =
                Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(Self::hash160(&sig.0.to_bytes())));

            input.final_script_sig = Some(script);

            let mut witness = Witness::new();
            witness.push(sig.1.to_vec());
            witness.push(sig.0.to_bytes());

            input.final_script_witness = Some(witness);
        }
    }

    fn finalize_p2tr(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];

        if input.tap_key_sig.is_some() {
            let mut witness = Witness::new();
            witness.push(input.tap_key_sig.unwrap().to_vec());

            if !input.tap_scripts.is_empty() {
                let (control_block, script_leaf) = input.tap_scripts.first_key_value().unwrap();

                let (script, _) = script_leaf;
                witness.push(script.as_bytes().to_vec());
                witness.push(control_block.serialize())
            }

            input.final_script_witness = Some(witness);
        }
    }

    fn clear_finalized_input(&mut self, index: usize) {
        let input = &mut self.psbt.inputs[index];
        input.tap_key_sig = None;
        input.tap_scripts = BTreeMap::new();
        input.tap_internal_key = None;
        input.tap_merkle_root = None;
        input.tap_script_sigs = BTreeMap::new();

        input.partial_sigs = BTreeMap::new();
        input.sighash_type = None;
        input.redeem_script = None;
        input.witness_script = None;
        input.bip32_derivation = BTreeMap::new();
        input.unknown = BTreeMap::new();
    }

    fn sign_p2pkh(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, false)?;

        let prevout = &self.prevouts[index];

        let hash = self.sighash_cache.legacy_hash(
            index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All.to_u32(),
        )?;

        let sig = Self::sign_ecdsa(&hash, &key)?;
        self.psbt.inputs[index]
            .partial_sigs
            .insert(key.public_key().0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2sh_nested_p2wpkh(&mut self, index: usize) -> Result<()> {
        let prevout = &self.prevouts[index].clone();
        let key = self.get_private_key(index, false)?;
        let pub_key = key.public_key();

        let script = Script::new_v0_p2wpkh(&WPubkeyHash::from_hash(Self::hash160(
            &pub_key.to_compressed(),
        )));

        let hash = self.sighash_cache.segwit_hash(
            index,
            &script.p2wpkh_script_code().expect("must be v0_p2wpkh"),
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let sig = Self::sign_ecdsa(&hash, &key)?;

        self.psbt.inputs[index]
            .partial_sigs
            .insert(pub_key.0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2wpkh(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, false)?;
        let prevout = &self.prevouts[index];

        let hash = self.sighash_cache.segwit_hash(
            index,
            &prevout
                .script_pubkey
                .p2wpkh_script_code()
                .expect("must be v0_p2wpkh"),
            prevout.value,
            EcdsaSighashType::All,
        )?;
        let sig = Self::sign_ecdsa(&hash, &key)?;

        self.psbt.inputs[index]
            .partial_sigs
            .insert(key.public_key().0, EcdsaSig::sighash_all(sig));

        Ok(())
    }

    fn sign_p2tr(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, true)?;

        let key_pair = bitcoin::schnorr::UntweakedKeyPair::from_seckey_slice(
            &SECP256K1_ENGINE,
            &key.to_bytes(),
        )?
        .tap_tweak(&SECP256K1_ENGINE, None);

        let hash = self.sighash_cache.taproot_hash(
            index,
            &Prevouts::All(self.prevouts.as_slice()),
            None,
            None,
            SchnorrSighashType::Default,
        )?;

        let msg = Message::from_slice(&hash[..])?;
        let sig = SECP256K1_ENGINE.sign_schnorr(&msg, &key_pair.to_inner());

        self.psbt.inputs[index].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    fn sign_p2tr_script(&mut self, index: usize) -> Result<()> {
        let key = self.get_private_key(index, true)?;

        let key_pair = bitcoin::schnorr::UntweakedKeyPair::from_seckey_slice(
            &SECP256K1_ENGINE,
            &key.to_bytes(),
        )?;

        let input = self.psbt.inputs[index].clone();
        let (_, script_leaf) = input.tap_scripts.first_key_value().unwrap();

        let (script, leaf_version) = script_leaf;
        let hash = self.sighash_cache.taproot_script_spend_signature_hash(
            index,
            &Prevouts::All(&self.prevouts.clone()),
            TapLeafHash::from_script(script, leaf_version.clone()),
            SchnorrSighashType::Default,
        )?;

        let msg = Message::from_slice(&hash[..])?;
        let sig = SECP256K1_ENGINE.sign_schnorr(&msg, &key_pair);
        self.psbt.inputs[index].tap_key_sig = Some(SchnorrSig {
            hash_ty: SchnorrSighashType::Default,
            sig,
        });

        Ok(())
    }

    pub fn sign(&mut self) -> Result<()> {
        self.prevouts = self.prevouts()?;

        for idx in 0..self.prevouts.len() {
            let prevout = &self.prevouts[idx];

            if prevout.script_pubkey.is_p2pkh() {
                self.sign_p2pkh(idx)?;

                if self.auto_finalize {
                    self.finalize_p2pkh(idx);
                }
            } else if prevout.script_pubkey.is_p2sh() {
                self.sign_p2sh_nested_p2wpkh(idx)?;

                if self.auto_finalize {
                    self.finalize_p2sh_nested_p2wpkh(idx);
                }
            } else if prevout.script_pubkey.is_v0_p2wpkh() {
                self.sign_p2wpkh(idx)?;

                if self.auto_finalize {
                    self.finalize_p2wpkh(idx);
                }
            } else if !self.psbt.inputs.first().unwrap().tap_scripts.is_empty() {
                self.sign_p2tr_script(idx)?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            } else if prevout.script_pubkey.is_v1_p2tr() {
                self.sign_p2tr(idx)?;

                if self.auto_finalize {
                    self.finalize_p2tr(idx);
                }
            }

            if self.auto_finalize {
                self.clear_finalized_input(idx);
            }
        }

        Ok(())
    }
}

pub fn sign_psbt(
    chain_type: &str,
    derivation_path: &str,
    keystore: &mut Keystore,
    psbt_input: PsbtInput,
) -> Result<PsbtOutput> {
    let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_input.psbt)?);
    let mut psbt = Psbt::consensus_decode(&mut reader)?;

    let mut signer = PsbtSigner::new(
        &mut psbt,
        keystore,
        chain_type,
        derivation_path,
        psbt_input.auto_finalize,
    );
    signer.sign()?;

    let mut vec = Vec::<u8>::new();
    let mut writer = Cursor::new(&mut vec);
    psbt.consensus_encode(&mut writer)?;

    return Ok(PsbtOutput { psbt: vec.to_hex() });
}

pub fn sign_psbts(
    chain_type: &str,
    derivation_path: &str,
    keystore: &mut Keystore,
    psbts_input: PsbtsInput,
) -> Result<PsbtsOutput> {
    let mut outputs = Vec::<String>::new();

    for item in psbts_input.psbts {
        let psbt_input = PsbtInput {
            psbt: item,
            auto_finalize: psbts_input.auto_finalize,
        };

        let output = sign_psbt(chain_type, derivation_path, keystore, psbt_input)?;
        outputs.push(output.psbt);
    }

    Ok(PsbtsOutput { psbts: outputs })
}

#[cfg(test)]
mod tests {
    use crate::psbt::PsbtSigner;
    use crate::tests::sample_hd_keystore;
    use crate::transaction::PsbtInput;
    use crate::BtcKinAddress;
    use bitcoin::consensus::Decodable;
    use bitcoin::psbt::serialize::{Deserialize, Serialize};
    use bitcoin::psbt::Psbt;
    use bitcoin::schnorr::TapTweak;
    use bitcoin::util::bip32::{DerivationPath, KeySource};
    use bitcoin::{schnorr, Script, Transaction, TxOut, Witness};
    use secp256k1::schnorr::Signature;
    use secp256k1::{Message, XOnlyPublicKey};
    use std::io::Cursor;
    use std::str::FromStr;
    use tcx_common::{FromHex, ToHex};
    use tcx_constants::{CoinInfo, CurveType};
    use tcx_primitive::{PublicKey, SECP256K1_ENGINE};

    #[test]
    fn test_sign_psbt_no_script() {
        let mut hd = sample_hd_keystore();
        let coin_info = CoinInfo {
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/1'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
        };

        let account = hd.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let psbt_input = PsbtInput {
            psbt: "70736274ff0100db0200000001fa4c8d58b9b6c56ed0b03f78115246c99eb70f99b837d7b4162911d1016cda340200000000fdffffff0350c30000000000002251202114eda66db694d87ff15ddd5d3c4e77306b6e6dd5720cbd90cd96e81016c2b30000000000000000496a47626274340066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229ec20acf33c17e5a6c92cced9f1d530cccab7aa3e53400456202f02fac95e9c481fa00d47b1700000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233d80f03000001012be3bf1d00000000002251208f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c23301172066f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e00000000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("BITCOIN", "m/86'/1'/0'", &mut hd, psbt_input).unwrap();
        let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_output.psbt).unwrap());
        let psbt = Psbt::consensus_decode(&mut reader).unwrap();
        let tx = psbt.extract_tx();
        let sig = schnorr::SchnorrSig::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();

        let data =
            Vec::<u8>::from_hex("3a66cf6ec1a87b10b86fa358baf64484bba8c61c9828e5cbe2eb8a3d4bbf190c")
                .unwrap();
        let msg = Message::from_slice(&data).unwrap();
        let x_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let tweak_pub_key = x_pub_key.tap_tweak(&SECP256K1_ENGINE, None);

        assert!(sig.sig.verify(&msg, &tweak_pub_key.0.to_inner()).is_ok());
    }

    #[test]
    fn test_sign_psbt_script() {
        let mut hd = sample_hd_keystore();
        let coin_info = CoinInfo {
            coin: "BITCOIN".to_string(),
            derivation_path: "m/86'/1'/0'/0/0".to_string(),
            curve: CurveType::SECP256k1,
            network: "TESTNET".to_string(),
            seg_wit: "VERSION_1".to_string(),
        };

        let account = hd.derive_coin::<BtcKinAddress>(&coin_info).unwrap();

        let psbt_input = PsbtInput {
            psbt: "70736274ff01005e02000000012bd2f6479f3eeaffe95c03b5fdd76a873d346459114dec99c59192a0cb6409e90000000000ffffffff01409c000000000000225120677cc88dc36a75707b370e27efff3e454d446ad55004dac1685c1725ee1a89ea000000000001012b50c3000000000000225120a9a3350206de400f09a73379ec1bcfa161fc11ac095e5f3d7354126f0ec8e87f6215c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0d2956573f010fa1a3c135279c5eb465ec2250205dcdfe2122637677f639b1021356c963cd9c458508d6afb09f3fa2f9b48faec88e75698339a4bbb11d3fc9b0efd570120aff94eb65a2fe773a57c5bd54e62d8436a5467573565214028422b41bd43e29bad200aee0509b16db71c999238a4827db945526859b13c95487ab46725357c9a9f25ac20113c3a32a9d320b72190a04a020a0db3976ef36972673258e9a38a364f3dc3b0ba2017921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4ba203bb93dfc8b61887d771f3630e9a63e97cbafcfcc78556a474df83a31a0ef899cba2040afaf47c4ffa56de86410d8e47baa2bb6f04b604f4ea24323737ddc3fe092dfba2079a71ffd71c503ef2e2f91bccfc8fcda7946f4653cef0d9f3dde20795ef3b9f0ba20d21faf78c6751a0d38e6bd8028b907ff07e9a869a43fc837d6b3f8dff6119a36ba20f5199efae3f28bb82476163a7e458c7ad445d9bffb0682d10d3bdb2cb41f8e8eba20fa9d882d45f4060bdb8042183828cd87544f1ea997380e586cab77d5fd698737ba569cc001172050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00000".to_string(),
            auto_finalize: true,
        };

        let psbt_output = super::sign_psbt("BITCOIN", "m/86'/1'/0'", &mut hd, psbt_input).unwrap();
        let mut reader = Cursor::new(Vec::<u8>::from_hex(psbt_output.psbt).unwrap());
        let psbt = Psbt::consensus_decode(&mut reader).unwrap();
        let tx = psbt.extract_tx();
        let witness = tx.input[0].witness.to_vec();
        let sig = schnorr::SchnorrSig::from_slice(&witness[0]).unwrap();

        let data =
            Vec::<u8>::from_hex("56b6c5fd09753fbbbeb8f530308e4f7d2f404e02da767f033e926d27fcc2f37e")
                .unwrap();
        let msg = Message::from_slice(&data).unwrap();
        let x_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        let script = witness[1].to_hex();
        let control_block = witness[2].to_hex();
        assert_eq!(script, "20aff94eb65a2fe773a57c5bd54e62d8436a5467573565214028422b41bd43e29bad200aee0509b16db71c999238a4827db945526859b13c95487ab46725357c9a9f25ac20113c3a32a9d320b72190a04a020a0db3976ef36972673258e9a38a364f3dc3b0ba2017921cf156ccb4e73d428f996ed11b245313e37e27c978ac4d2cc21eca4672e4ba203bb93dfc8b61887d771f3630e9a63e97cbafcfcc78556a474df83a31a0ef899cba2040afaf47c4ffa56de86410d8e47baa2bb6f04b604f4ea24323737ddc3fe092dfba2079a71ffd71c503ef2e2f91bccfc8fcda7946f4653cef0d9f3dde20795ef3b9f0ba20d21faf78c6751a0d38e6bd8028b907ff07e9a869a43fc837d6b3f8dff6119a36ba20f5199efae3f28bb82476163a7e458c7ad445d9bffb0682d10d3bdb2cb41f8e8eba20fa9d882d45f4060bdb8042183828cd87544f1ea997380e586cab77d5fd698737ba569c");
        assert_eq!(control_block, "c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0d2956573f010fa1a3c135279c5eb465ec2250205dcdfe2122637677f639b1021356c963cd9c458508d6afb09f3fa2f9b48faec88e75698339a4bbb11d3fc9b0e");

        assert!(sig.sig.verify(&msg, &x_pub_key).is_ok());
    }

    #[test]
    fn test_sign_psbt_multipayment() {
        let mut hd = sample_hd_keystore();

        let raw_tx = "02000000054adc61444e5a4dd7021e52dc6f5adadd9a3286d346f5d9f023ebcde2af80a0ae0000000000ffffffff4adc61444e5a4dd7021e52dc6f5adadd9a3286d346f5d9f023ebcde2af80a0ae0100000000ffffffff12cc8049bf85b5e18cb2be8aa7aefc3afb8df4ec5c1f766750014cc95ca2dc130000000000ffffffff729e6570928cc65200f1d53def65a7934d2e9b543059d90598ed1d166af422010100000000ffffffffa126724475cd2f3252352b3543c8455c7999a8283883bd7a712a7d66609d92d80100000000ffffffff02409c00000000000022512036079c540758a51a86eeaf9e17668d4d8543d8b1b7e56fe2da0982c390c5655ef8fa0700000000002251209303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea0615500000000";
        let tx = Transaction::deserialize(&Vec::from_hex(&raw_tx).unwrap()).unwrap();

        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        let fake_pub_key = secp256k1::PublicKey::from_slice(
            &Vec::<u8>::from_hex(
                "0266f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e",
            )
            .unwrap(),
        )
        .unwrap();
        let fake_xonly_pub_key = XOnlyPublicKey::from_slice(
            Vec::<u8>::from_hex("66f873ad53d80688c7739d0d268acd956366275004fdceab9e9fc30034a4229e")
                .unwrap()
                .as_slice(),
        )
        .unwrap();

        psbt.inputs[0].tap_key_origins.insert(
            fake_xonly_pub_key,
            (
                Default::default(),
                (
                    Default::default(),
                    DerivationPath::from_str("m/86'/1'/0'/0/0").unwrap(),
                ),
            ),
        );
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: 20000,
            script_pubkey: BtcKinAddress::from_str(
                "tb1p3ax2dfecfag2rlsqewje84dgxj6gp3jkj2nk4e3q9cwwgm93cgesa0zwj4",
            )
            .unwrap()
            .script_pubkey(),
        });

        psbt.inputs[1].tap_key_origins.insert(
            fake_xonly_pub_key,
            (
                Default::default(),
                (
                    Default::default(),
                    DerivationPath::from_str("m/86'/1'/0'/1/53").unwrap(),
                ),
            ),
        );
        psbt.inputs[1].witness_utxo = Some(TxOut {
            value: 283000,
            script_pubkey: BtcKinAddress::from_str(
                "tb1pjvp6z9shfhfpafrnwen9j452cf8tdwpgc0hfnzvz62aqwr4qv92sg7qj9r",
            )
            .unwrap()
            .script_pubkey(),
        });

        psbt.inputs[2].bip32_derivation.insert(
            fake_pub_key,
            (
                Default::default(),
                DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
            ),
        );
        psbt.inputs[2].witness_utxo = Some(TxOut {
            value: 100000,
            script_pubkey: BtcKinAddress::from_str("tb1qrfaf3g4elgykshfgahktyaqj2r593qkrae5v95")
                .unwrap()
                .script_pubkey(),
        });

        psbt.inputs[3].bip32_derivation.insert(
            fake_pub_key,
            (
                Default::default(),
                DerivationPath::from_str("m/49'/1'/0'/0/0").unwrap(),
            ),
        );
        psbt.inputs[3].witness_utxo = Some(TxOut {
            value: 100000,
            script_pubkey: BtcKinAddress::from_str("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB")
                .unwrap()
                .script_pubkey(),
        });

        psbt.inputs[4].bip32_derivation.insert(
            fake_pub_key,
            (
                Default::default(),
                DerivationPath::from_str("m/44'/1'/0'/0/0").unwrap(),
            ),
        );
        psbt.inputs[4].witness_utxo = Some(TxOut {
            value: 100000,
            script_pubkey: BtcKinAddress::from_str("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
                .unwrap()
                .script_pubkey(),
        });

        let mut signer = PsbtSigner::new(&mut psbt, &mut hd, "BITCOIN", "", true);
        signer.sign().unwrap();

        let tx = psbt.extract_tx();

        let msg = Message::from_slice(
            &Vec::from_hex("f01ba76b329132e48188ad10d00791647ee6d2f7fee5ef397f3481993c898de3")
                .unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&tx.input[0].witness.to_vec()[0]).unwrap();
        let pub_key = XOnlyPublicKey::from_slice(
            &Vec::from_hex("8f4ca6a7384f50a1fe00cba593d5a834b480c65692a76ae6202e1ce46cb1c233")
                .unwrap(),
        )
        .unwrap();
        assert!(sig.verify(&msg, &pub_key).is_ok());

        let msg = Message::from_slice(
            &Vec::from_hex("d0691b5ac1b338b9341790ea69417cb454cf346a718342fb4a846dbb8ae142e8")
                .unwrap(),
        )
        .unwrap();
        let sig = Signature::from_slice(&tx.input[1].witness.to_vec()[0]).unwrap();
        let pub_key = XOnlyPublicKey::from_slice(
            &Vec::from_hex("9303a116174dd21ea473766659568ac24eb6b828c3ee998982d2ba070ea06155")
                .unwrap(),
        )
        .unwrap();
        assert!(sig.verify(&msg, &pub_key).is_ok());

        assert_eq!(tx.input[2].witness.to_vec()[0].to_hex(), "3044022022c2feaa4a225496fc6789c969fb776da7378f44c588ad812a7e1227ebe69b6302204fc7bf5107c6d02021fe4833629bc7ab71cefe354026ebd0d9c0da7d4f335f9401");
        assert_eq!(
            tx.input[2].witness.to_vec()[1].to_hex(),
            "02e24f625a31c9a8bae42239f2bf945a306c01a450a03fd123316db0e837a660c0"
        );

        assert_eq!(tx.input[3].witness.to_vec()[0].to_hex(), "3045022100dec4d3fd189b532ef04f41f68319ff7dc6a7f2351a0a8f98cb7f1ec1f6d71c7a02205e507162669b642fdb480a6c496abbae5f798bce4fd42cc390aa58e3847a1b9101");
        assert_eq!(
            tx.input[3].witness.to_vec()[1].to_hex(),
            "031aee5e20399d68cf0035d1a21564868f22bc448ab205292b4279136b15ecaebc"
        );

        assert_eq!(tx.input[4].script_sig.to_hex(), "483045022100ca32abc7b180c84cf76907e4e1e0c3f4c0d6e64de23b0708647ac6fee1c04c5b02206e7412a712424eb9406f18e00a42e0dffbfb5901932d1ef97843d9273865550e0121033d710ab45bb54ac99618ad23b3c1da661631aa25f23bfe9d22b41876f1d46e4e");
    }
}
