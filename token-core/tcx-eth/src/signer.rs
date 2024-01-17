use crate::transaction::{
    EthMessageInput, EthMessageOutput, EthRecoverAddressInput, EthRecoverAddressOutput, EthTxInput,
    EthTxOutput, SignatureType,
};
use crate::Result;
use ethereum_types::{Address, H256, U256, U64};
use ethers::signers::LocalWallet;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::transaction::eip2930::{AccessList, AccessListItem};
use ethers::types::{Bytes, Eip1559TransactionRequest, Signature, TransactionRequest};
use ethers::utils::{hash_message, keccak256};
use keccak_hash::keccak;
use std::str::FromStr;
use tcx_common::{utf8_or_hex_to_bytes, FromHex, ToHex};
use tcx_keystore::{Keystore, MessageSigner, SignatureParameters, TransactionSigner};

impl TransactionSigner<EthTxInput, EthTxOutput> for Keystore {
    fn sign_transaction(
        &mut self,
        params: &SignatureParameters,
        tx: &EthTxInput,
    ) -> tcx_keystore::Result<EthTxOutput> {
        let private_key = self.get_private_key(params.curve, &params.derivation_path)?;
        tx.sign_transaction(&private_key.to_bytes())
    }
}

impl MessageSigner<EthMessageInput, EthMessageOutput> for Keystore {
    fn sign_message(
        &mut self,
        params: &SignatureParameters,
        message: &EthMessageInput,
    ) -> tcx_keystore::Result<EthMessageOutput> {
        let private_key = self.get_private_key(params.curve, &params.derivation_path)?;
        if message.signature_type == SignatureType::PersonalSign as i32 {
            message.sign_message(&private_key.to_bytes())
        } else {
            message.ec_sign(&private_key.to_bytes())
        }
    }
}

impl EthTxInput {
    pub fn sign_transaction(&self, private_key: &[u8]) -> Result<EthTxOutput> {
        let wallet = LocalWallet::from_bytes(private_key)?;
        let chain_id = parse_u64(self.chain_id.as_str())?;
        let ret_result = if self.tx_type.to_lowercase() == "0x02"
            || self.tx_type.to_lowercase() == "0x2"
            || self.tx_type == "02"
        {
            let eip1559_tx = Eip1559TransactionRequest::new()
                .nonce(U256::from_dec_str(&self.nonce)?)
                .to(self.to.parse::<Address>()?)
                .value(U256::from_dec_str(&self.value)?)
                .gas(U256::from_dec_str(&self.gas_limit)?)
                .data(Bytes::from_str(&self.data)?)
                .chain_id(chain_id)
                .max_priority_fee_per_gas(U256::from_dec_str(&self.max_priority_fee_per_gas)?)
                .max_fee_per_gas(U256::from_dec_str(&self.max_fee_per_gas)?)
                .access_list(self.parse_access_list_item()?);

            let signature =
                wallet.sign_transaction_sync(&TypedTransaction::Eip1559(eip1559_tx.clone()))?;
            let sign_result = eip1559_tx.rlp_signed(&signature);

            let mut sign_bytes = vec![];
            sign_bytes.push(parse_u64(self.tx_type.as_str())?.byte(0));
            sign_bytes.extend(sign_result.as_ref().iter());

            let signature = sign_bytes.to_hex();
            let tx_hash = keccak(sign_bytes).as_ref().to_0x_hex();
            EthTxOutput { signature, tx_hash }
        } else {
            let legacy_tx = TransactionRequest::new()
                .nonce(U256::from_dec_str(&self.nonce)?)
                .to(self.to.parse::<Address>()?)
                .value(U256::from_dec_str(&self.value)?)
                .gas_price(U256::from_dec_str(&self.gas_price)?)
                .gas(U256::from_dec_str(&self.gas_limit)?)
                .data(Bytes::from_str(&self.data)?)
                .chain_id(chain_id);

            let signature: Signature =
                wallet.sign_transaction_sync(&TypedTransaction::Legacy(legacy_tx.clone()))?;

            let sign_result = legacy_tx.rlp_signed(&signature);
            let signature = sign_result.to_hex();
            let tx_hash = keccak(sign_result).as_ref().to_0x_hex();

            EthTxOutput { signature, tx_hash }
        };

        Ok(ret_result)
    }

    fn parse_access_list_item(&self) -> Result<AccessList> {
        if self.access_list.is_empty() {
            return Ok(AccessList::default());
        }
        let mut ret_access_list = AccessList::default();
        for access in &self.access_list {
            let item = AccessListItem {
                address: ethereum_types::Address::from_str(&access.address)?,
                storage_keys: {
                    let mut storage_keys: Vec<H256> = Vec::new();
                    for key in &access.storage_keys {
                        let key_bytes: [u8; 32] =
                            Vec::from_hex_auto(key.as_str())?.try_into().unwrap();
                        storage_keys.push(H256(key_bytes));
                    }
                    storage_keys
                },
            };
            ret_access_list.0.push(item);
        }
        Ok(ret_access_list)
    }
}

impl EthMessageInput {
    pub fn sign_message(&self, private_key: &[u8]) -> Result<EthMessageOutput> {
        let wallet = LocalWallet::from_bytes(private_key)?;
        let message = utf8_or_hex_to_bytes(&self.message)?;
        let message_hash = hash_message(message);
        let sign_result = wallet.sign_hash(message_hash)?;

        let signature = format!("0x{}", sign_result.to_string());
        Ok(EthMessageOutput { signature })
    }

    pub fn ec_sign(&self, private_key: &[u8]) -> Result<EthMessageOutput> {
        let wallet = LocalWallet::from_bytes(private_key)?;
        let message = utf8_or_hex_to_bytes(&self.message)?;

        let h256_hash = H256(keccak256(message));
        let sign_result = wallet.sign_hash(h256_hash)?;
        let signature = format!("0x{}", sign_result.to_string());
        Ok(EthMessageOutput { signature })
    }
}

impl EthRecoverAddressInput {
    pub fn recover_address(&self) -> Result<EthRecoverAddressOutput> {
        let signature = Signature::from_str(&self.signature)?;
        let message = utf8_or_hex_to_bytes(&self.message)?;
        let h256_hash = H256(keccak256(message));
        let address = signature.recover(h256_hash)?;
        Ok(EthRecoverAddressOutput {
            address: address.0.to_0x_hex(),
        })
    }
}

fn parse_u64(s: &str) -> Result<U64> {
    if let Some(s) = s.strip_prefix("0x") {
        Ok(U64::from_str_radix(s, 16)?)
    } else {
        let r = U64::from_dec_str(s);
        if r.is_err() {
            return Ok(U64::from_str_radix(s, 16)?);
        }
        Ok(r?)
    }
}

#[cfg(test)]
mod test {
    use crate::transaction::{
        AccessList, EthMessageInput, EthMessageOutput, EthRecoverAddressInput, EthTxInput,
        EthTxOutput, SignatureType,
    };
    use tcx_constants::{CurveType, TEST_MNEMONIC, TEST_PASSWORD};
    use tcx_keystore::{Keystore, MessageSigner, Metadata, SignatureParameters, TransactionSigner};

    fn private_key_store(key: &str) -> Keystore {
        let mut ks = Keystore::from_private_key(
            key,
            "imToken1",
            CurveType::SECP256k1,
            Metadata::default(),
            None,
        )
        .unwrap();
        ks.unlock_by_password("imToken1").unwrap();
        ks
    }

    #[test]
    fn test_eip155_transaction() {
        let tx = EthTxInput {
            nonce: "33738".to_string(),
            gas_price: "5000000000".to_string(),
            gas_limit: "50000".to_string(),
            to: "0x6031564e7b2f5cc33737807b2e58daff870b590b".to_string(),
            value: "607001513671985".to_string(),
            data: "".to_string(),
            chain_id: "42".to_string(),
            tx_type: "00".to_string(),
            max_fee_per_gas: "".to_string(),
            max_priority_fee_per_gas: "".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let tx_output = keystore.sign_transaction(&params, &tx).unwrap();

        assert_eq!(
            tx_output.tx_hash,
            "0x17fd692605405e051ac738ddf3d9b58185eaac14e434839d1453e653c5c23a1a"
        );
        assert_eq!(tx_output.signature, "f86d8283ca85012a05f20082c350946031564e7b2f5cc33737807b2e58daff870b590b870228108d99bd318078a09d56ef5b7ba4d6e2c4b9367ab263beb6bc2926bb9170ff2f42f0e25cbdec9aa7a062b6e1b702b1a34e887d6a3f693bdc8fbcd92e2963c12dfcffd255022d892fbe");
    }

    #[test]
    fn test_etc_transaction() {
        let tx = EthTxInput {
            nonce: "33738".to_string(),
            gas_price: "5000000000".to_string(),
            gas_limit: "50000".to_string(),
            to: "0x6031564e7b2f5cc33737807b2e58daff870b590b".to_string(),
            value: "607001513671985".to_string(),
            data: "".to_string(),
            chain_id: "61".to_string(),
            tx_type: "00".to_string(),
            max_fee_per_gas: "".to_string(),
            max_priority_fee_per_gas: "".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("4646464646464646464646464646464646464646464646464646464646464646");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let tx_output = keystore.sign_transaction(&params, &tx).unwrap();

        assert_eq!(
            tx_output.tx_hash,
            "0x6421324e5b1dcf30ff7b37e381eb94c8dad1f893d25efa8420aa653e9f19f51f"
        );
        assert_eq!(tx_output.signature, "f86e8283ca85012a05f20082c350946031564e7b2f5cc33737807b2e58daff870b590b870228108d99bd3180819ea0622bf0fd7e3b042cf2fc4cb62c61435f680f2dc3747a5d4e7a792aae0b3cf84fa07647e7df4158b50e71c63dbaccdff9f7d03f20f6a8dffd7295bdb6e906a4b89f");
    }

    #[test]
    fn test_eip1559_transaction() {
        let tx = EthTxInput {
            nonce: "549".to_string(),
            gas_price: "".to_string(),
            gas_limit: "21000".to_string(),
            to: "0x03e2B0f5369297a2E7A13d6F8e6d4BFbB9cf7dC7".to_string(),
            value: "500000000000000".to_string(),
            data: "".to_string(),
            chain_id: "42".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "2000000000".to_string(),
            max_priority_fee_per_gas: "2000000000".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("cce64585e3b15a0e4ee601a467e050c9504a0db69a559d7ec416fa25ad3410c2");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let tx_output = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x812824e60c60f8d46aa5e211c8e4a50baf92350c98c83e71c379d273ce0a0787"
        );
        assert_eq!(tx_output.signature, "02f8732a820225847735940084773594008252089403e2b0f5369297a2e7a13d6f8e6d4bfbb9cf7dc78701c6bf5263400080c001a0b6bd8b2f4d94910d72906cb20f83e9ec0808e00e92e8338f68a496ee77c29245a00c77abda1141f4991774b240f0fcd55faa19584e06d2bd43d4d5ceb6d4381207");

        let tx = EthTxInput {
            nonce: "548".to_string(),
            gas_price: "".to_string(),
            gas_limit: "220".to_string(),
            to: "0x87e65b8280098da8f9bb3a69643573378da87542".to_string(),
            value: "44902".to_string(),
            data: "0x3400711e1d0bfbcf".to_string(),
            chain_id: "42".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "2298206284".to_string(),
            max_priority_fee_per_gas: "163".to_string(),
            access_list: vec![],
        };
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x90b1a2325ee4acb953e67a9b05c5b7048dc30ac222f8736b82ea4222b5a5721e"
        );
        assert_eq!(tx_output.signature, "02f8722a82022481a38488fbd84c81dc9487e65b8280098da8f9bb3a69643573378da8754282af66883400711e1d0bfbcfc001a03e202f7d17126f8cc3f17a3fb96508d52d7cdd93dc862481ff9b9653c71bb254a04d34bef9821db11b7f5b6d4b303b07793248fc0f34223b5884601f5511da3abc");

        let tx = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "".to_string(),
            gas_limit: "14298499".to_string(),
            to: "0xef970655297d1234174bcfe31ee803aaa97ad0ca".to_string(),
            value: "11".to_string(),
            data: "0xee".to_string(),
            chain_id: "130".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "850895266216".to_string(),
            max_priority_fee_per_gas: "69".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("0626687a500e27ffca881fe129541f1a2033aedd32186a0540c10e3d0588b4f7");
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0xa8b660bec405dca182e526401b03aab04f0f3547ba7382e89f73bb3b3aae0829"
        );
        assert_eq!(tx_output.signature, "02f86a8182084585c61d4f61a883da2d8394ef970655297d1234174bcfe31ee803aaa97ad0ca0b81eec001a060364c7bddc7d080dcdbf859a6d8316b297d27c4ebd6288ccc6591e5870fff74a05e9b1a2074062dbf84c757a940a92d0d5712eaebd1043665478f16deb26347c8");

        let mut access_list = vec![];
        access_list.push(AccessList {
            address: "0x70b361fc3a4001e4f8e4e946700272b51fe4f0c4".to_string(),
            storage_keys: vec![
                "0x8419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63".to_string(),
                "0x8a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3".to_string(),
                "0x897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab9".to_string(),
            ],
        });
        let tx = EthTxInput {
            nonce: "4".to_string(),
            gas_price: "".to_string(),
            gas_limit: "54".to_string(),
            to: "0xd5539a0e4d27ebf74515fc4acb38adcc3c513f25".to_string(),
            value: "64".to_string(),
            data: "0xf579eebd8a5295c6f9c86e".to_string(),
            chain_id: "276".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "963240322143".to_string(),
            max_priority_fee_per_gas: "28710".to_string(),
            access_list,
        };
        let mut keystore =
            private_key_store("c69e17f597758c69dc181956060bef908e5a89fc00313aac0da6e387121648c2");
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x0a0b6c71e52fcb14ba60e271e71c410783beb2448e06822c5f148f9d3fe796c3"
        );
        assert_eq!(tx_output.signature, "02f8f18201140482702685e04598e45f3694d5539a0e4d27ebf74515fc4acb38adcc3c513f25408bf579eebd8a5295c6f9c86ef87cf87a9470b361fc3a4001e4f8e4e946700272b51fe4f0c4f863a08419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63a08a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3a0897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab980a0c34ce2038e430ecf67194a78cf47da1ff6c6fff427a43d4a7caf0cec52d6be0da065f6bf0e34a511bf3b81510d46510b3420fee86637120df4a56ef07fc8704e40");

        let mut access_list = vec![];
        access_list.push(AccessList {
            address: "0x55a7ce45514b6e71743bbb67e9959bd19eefb8ed".to_string(),
            storage_keys: vec![
                "0x766d2c1aef5f615a3f935de247800dfbf9a8bb7be5a43795f78f9c83f24f013d".to_string(),
                "0xb34339a846e7a304ad82e20b3cf05260698566efc1c6488bf851689a279d262e".to_string(),
            ],
        });
        let tx = EthTxInput {
            nonce: "6".to_string(),
            gas_price: "".to_string(),
            gas_limit: "10884139".to_string(),
            to: "0xd24911709fa01130804188b5c76ed65bfdfd6a05".to_string(),
            value: "4990".to_string(),
            data: "0xe9290f2d3d754ba522".to_string(),
            chain_id: "225".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "2984486799".to_string(),
            max_priority_fee_per_gas: "183".to_string(),
            access_list,
        };
        let mut keystore =
            private_key_store("272bbc8b388511b2fb17315ec77c802187368e82459081e0ce3229ed30b8001c");
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0xdec9d2ca302a5421a9ab5ce568899eb2dae6ba89b2051a5e15be8506246524c4"
        );
        assert_eq!(tx_output.signature, "02f8d081e10681b784b1e3a78f83a6142b94d24911709fa01130804188b5c76ed65bfdfd6a0582137e89e9290f2d3d754ba522f85bf8599455a7ce45514b6e71743bbb67e9959bd19eefb8edf842a0766d2c1aef5f615a3f935de247800dfbf9a8bb7be5a43795f78f9c83f24f013da0b34339a846e7a304ad82e20b3cf05260698566efc1c6488bf851689a279d262e01a0fec0c018ec049c8278e346b290cd74d68cc5b18fac6c8dc9abbe7155367681cea02c2592c44cdae3d0a1017ab30f61486ddba1a45ba358e1c66e493b652e8827e1");

        let mut access_list = vec![];
        access_list.push(AccessList {
            address: "0x4824aec0a347a627d2bd88ae1f69a41b0665fed0".to_string(),
            storage_keys: vec![],
        });
        let tx = EthTxInput {
            nonce: "3".to_string(),
            gas_price: "".to_string(),
            gas_limit: "41708".to_string(),
            to: "0xaf9031dff5db0a02d25cd09b3cbb0d3f7f332faf".to_string(),
            value: "44939".to_string(),
            data: "0x4f".to_string(),
            chain_id: "365".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "259340687386".to_string(),
            max_priority_fee_per_gas: "223".to_string(),
            access_list,
        };
        let mut keystore =
            private_key_store("1515a472fde48c24c6e7f565397e683f3c3a33cb57bcd3bffc06444081aac1fb");
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x6dc6942e91746d1df6637b32cc7e3d4ec3bbe943d85cd8e32a30d6b6367558ed"
        );
        assert_eq!(tx_output.signature, "02f88382016d0381df853c61e8d81a82a2ec94af9031dff5db0a02d25cd09b3cbb0d3f7f332faf82af8b4fd7d6944824aec0a347a627d2bd88ae1f69a41b0665fed0c080a016fd2a3b319df64713a402c20c9f2cccf16449fb1ad850d1dd5defc3d154e680a012adb991599d3c7cc7279aaf7ebee8ed9278f0574fa5899ddbfd5688921b9d0f");

        let mut access_list = vec![];
        access_list.push(AccessList {
            address: "0x019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
            storage_keys: vec![],
        });
        access_list.push(AccessList {
            address: "0x1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
            storage_keys: vec![
                "0xd259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2".to_string(),
            ],
        });
        access_list.push(AccessList {
            address: "0xf1946eba70f89687d67493d8106f56c90ecba943".to_string(),
            storage_keys: vec![
                "0xb3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9".to_string(),
                "0x6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82".to_string(),
                "0x0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064".to_string(),
            ],
        });
        let tx = EthTxInput {
            nonce: "1".to_string(),
            gas_price: "".to_string(),
            gas_limit: "4286".to_string(),
            to: "0x6f4ecd70932d65ac08b56db1f4ae2da4391f328e".to_string(),
            value: "3490361".to_string(),
            data: "0x200184c0486d5f082a27".to_string(),
            chain_id: "63".to_string(),
            tx_type: "02".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list,
        };
        let mut keystore =
            private_key_store("d639ec503c8acc27d2a57a4477864d43aad1bf84c2270f47207ca372c7dc480b");
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0xf512934c8e6d1d1436488c9584eeb9b2d8bf1a8bc361d268c2a55aa31fb6f3c3"
        );
        assert_eq!(tx_output.signature, "02f901413f0181e285faac6c45d88210be946f4ecd70932d65ac08b56db1f4ae2da4391f328e833542398a200184c0486d5f082a27f8cbd694019fda53b3198867b8aae65320c9c55d74de1938c0f7941b976cdbc43cfcbeaad2623c95523981ea1e664ae1a0d259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2f87a94f1946eba70f89687d67493d8106f56c90ecba943f863a0b3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9a06a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82a00c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb206480a00d2e19fb7caa581e759fa73ef0fb83c8177e56c8370155dcd3ae9d207e113813a0671824c1c23407a0e695ada7e4a3a4e0d7bbe65ca930e46639862b732d63c921");
    }

    #[test]
    fn test_bsc_hex_chain_id() {
        let tx = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "0x38".to_string(),
            tx_type: "".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x1a3c3947ea626e00d6ff1493bcf929b9320d15ff088046990ef88a45f7d37623"
        );
        assert_eq!(tx_output.signature, "f868088504a817c8088302e248943535353535353535353535353535353535353535820200808194a003479f1d6be72af58b1d60750e155c435e435726b5b690f4d3e59f34bd55e578a0314d2b03d29dc3f87ff95c3427658952add3cf718d3b6b8604068fc3105e4442");
    }

    #[test]
    fn test_sign_tx_int_chain_id() {
        let tx = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "1".to_string(),
            tx_type: "".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();

        assert_eq!(
            tx_output.tx_hash,
            "0xa10172bcf5002ccd23bc1785fd6caf2f663a2430b6710ec539429230ec615073"
        );
        assert_eq!(tx_output.signature, "f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a0e57f7d1452aae9ff62ceb478f62d4ef038b76dbb6b698f4e0f64732022ba53bfa0389ad6a3648b9469c26127244e5e0d33b2a7ae170b0a14b20bec99aed5497895");
    }

    #[test]
    fn test_sign_tx_hex_chain_id() {
        let tx = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "A3".to_string(),
            tx_type: "".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x0e3cc87e9f4924a01edc5e09c27f9b1f9fcdb1c6a2a637fb28fd9efe39af42b0"
        );
        assert_eq!(tx_output.signature, "f869088504a817c8088302e2489435353535353535353535353535353535353535358202008082016aa083797cbcee123d37c6006d7518d71b02ecd8fcb5629f7c2ea3b8546350931755a032ddd89a62bc48e20a2a58d35dffa94ed1325a7e526cf94676b3726e1e538d88");
    }

    #[test]
    fn test_sign_big_chain_id() {
        let tx = EthTxInput {
            nonce: "8".to_string(),
            gas_price: "20000000008".to_string(),
            gas_limit: "189000".to_string(),
            to: "0x3535353535353535353535353535353535353535".to_string(),
            value: "512".to_string(),
            data: "".to_string(),
            chain_id: "1313161554".to_string(),
            tx_type: "".to_string(),
            max_fee_per_gas: "1076634600920".to_string(),
            max_priority_fee_per_gas: "226".to_string(),
            access_list: vec![],
        };
        let mut keystore =
            private_key_store("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let tx_output: EthTxOutput = keystore.sign_transaction(&params, &tx).unwrap();
        assert_eq!(
            tx_output.tx_hash,
            "0x66617e83ddfb63b5853e18a99af169651ad07ff5ca2eae812d9b79ceedda1174"
        );
        assert_eq!(tx_output.signature, "f86b088504a817c8088302e24894353535353535353535353535353535353535353582020080849c8a82c7a098c8ea50a36a00ee155db34340157fe34f76690466aca9e87f337ea3ba847cdba001b7742139071ef81c874b783c3aa1ef9261ac0096eba81e6936998d8c8ecd74");
    }

    #[test]
    fn test_sign_message() {
        let message = EthMessageInput {
            message: "Hello imToken".to_string(),
            signature_type: SignatureType::PersonalSign as i32,
        };
        let mut keystore =
            private_key_store("a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output: EthMessageOutput = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(
            output.signature,
            "0x1be38ff0ab0e6d97cba73cf61421f0641628be8ee91dcb2f73315e7fdf4d0e2770b0cb3cc7350426798d43f0fb05602664a28bb2c9fcf46a07fa1c8c4e322ec01b"
        );

        let message = EthMessageInput {
            message: "0xef678007d18427e6022059dbc264f27507cd1ffc".to_string(),
            signature_type: SignatureType::PersonalSign as i32,
        };
        let output: EthMessageOutput = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(
            output.signature,
            "0xb12a1c9d3a7bb722d952366b06bd48cb35bdf69065dee92351504c3716a782493c697de7b5e59579bdcc624aa277f8be5e7f42dc65fe7fcd4cc68fef29ff28c21b"
        );
    }

    #[test]
    fn test_sign_message_by_hd() {
        let mut keystore =
            Keystore::from_mnemonic(&TEST_MNEMONIC, &TEST_PASSWORD, Metadata::default()).unwrap();
        keystore.unlock_by_password(&TEST_PASSWORD).unwrap();

        let message = EthMessageInput {
            message: "hello world".to_string(),
            signature_type: SignatureType::PersonalSign as i32,
        };

        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };

        let output: EthMessageOutput = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(output.signature, "0x521d0e4b5808b7fbeb53bf1b17c7c6d60432f5b13b7aa3aaed963a894c3bd99e23a3755ec06fa7a61b031192fb5fab6256e180e086c2671e0a574779bb8593df1b");
    }

    #[test]
    fn test_ec_sign() {
        let message = EthMessageInput {
            message: "Hello imToken".to_string(),
            signature_type: SignatureType::EcSign as i32,
        };
        let mut keystore =
            private_key_store("3c9229289a6125f7fdf1885a77bb12c37a8d3b4962d936f7e3084dece32a3ca1");
        let params = SignatureParameters {
            curve: CurveType::SECP256k1,
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain_type: "ETHEREUM".to_string(),
            network: "".to_string(),
            seg_wit: "".to_string(),
        };
        let sign_output = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(
            sign_output.signature,
            "0x648081bc111e6116769bdb4396eebe17f58d3eddc0aeb04a868990deac9dfa2f322514a380fa66e0e864faaac6ef936092cdc022f5fd7d61cb501193ede537b31b"
        );
        let message = EthMessageInput {
            message: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            signature_type: SignatureType::EcSign as i32,
        };
        let sign_output = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(
            sign_output.signature,
            "0x65e4952899a8dcadf3a65a11bdac0f0cfdf93e0bae5c67674c78a72631de524d3cafe27ea71c86aa3fd838c6a50a0b09d6ece85a6dcf3ce85c30fdc51380ebdf1b"
        );

        let message = EthMessageInput {
            message: "0000000000000000".to_string(),
            signature_type: SignatureType::EcSign as i32,
        };
        let sign_output = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(
            sign_output.signature,
            "0xf85b21d47d4a828b0829bd3d0b7dbd19cb7fb8d75c24d03f424beddb38d6eb2456f3f438b18453826ce9eaf4b887a2e899e63e73c265dcd8ae0bc507184590a51c"
        );

        let message = EthMessageInput {
            message: "0x0000000000000000".to_string(),
            signature_type: SignatureType::EcSign as i32,
        };
        let sign_output = keystore.sign_message(&params, &message).unwrap();
        assert_eq!(
            sign_output.signature,
            "0xb35fe7d2e45098ef21264bc08d0c252a4a7b29f8a24ff25252e0f0c5b38e0ef0776bd12c9595353bdd4a118f8117182d543fa8f25d64a121c03c71f3a4e81b651b"
        );
    }

    #[test]
    fn test_address_recover() {
        let input = EthRecoverAddressInput {
            message: "0x0000000000000000".to_string(),
            signature: "0xb35fe7d2e45098ef21264bc08d0c252a4a7b29f8a24ff25252e0f0c5b38e0ef0776bd12c9595353bdd4a118f8117182d543fa8f25d64a121c03c71f3a4e81b651b".to_string(),
        };
        let output = input.recover_address().unwrap();
        println!("{}", output.address);
        assert_eq!(output.address, "0xed54a7c1d8634bb589f24bb7f05a5554b36f9618");
    }
}
