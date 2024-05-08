use super::Result;
use anyhow::anyhow;
use ethereum_types::{Address, H256, U256, U64};
use rlp::RlpStream;
use secp256k1::{ecdsa::RecoverableSignature, ecdsa::RecoveryId, Message, PublicKey};
use std::str::FromStr;
use tcx_common::{keccak256, Hash256, ToHex};
use tcx_primitive::SECP256K1_ENGINE;

pub fn to_eip155_v<T: Into<u64>>(recovery_id: T, chain_id: U64) -> U64 {
    U64::from(recovery_id.into() + 35 + chain_id.as_u64() * 2)
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionType {
    Legacy,
    Eip2930,
    Eip1559,
}

impl Default for TransactionType {
    fn default() -> Self {
        TransactionType::Legacy
    }
}

impl FromStr for TransactionType {
    type Err = anyhow::Error;

    fn from_str(tx_type: &str) -> Result<Self> {
        match tx_type {
            "0x01" | "1" | "01" => Ok(TransactionType::Eip2930),
            "0x02" | "2" | "02" => Ok(TransactionType::Eip1559),
            _ => Ok(TransactionType::Legacy),
        }
    }
}

pub type AccessList = Vec<AccessListItem>;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct AccessListItem {
    pub address: Address,
    pub storage_keys: Vec<H256>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Signature {
    pub v: U64,
    pub r: U256,
    pub s: U256,
}

impl ToHex for Signature {
    fn to_hex(&self) -> String {
        <[u8; 65]>::from(self).to_hex()
    }
}

impl From<&Signature> for [u8; 65] {
    fn from(src: &Signature) -> [u8; 65] {
        let mut sig = [0u8; 65];
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];
        src.r.to_big_endian(&mut r_bytes);
        src.s.to_big_endian(&mut s_bytes);
        sig[..32].copy_from_slice(&r_bytes);
        sig[32..64].copy_from_slice(&s_bytes);
        // TODO: What if we try to serialize a signature where
        // the `v` is not normalized?

        // The u64 to u8 cast is safe because `sig.v` can only ever be 27 or 28
        // here. Regarding EIP-155, the modification to `v` happens during tx
        // creation only _after_ the transaction is signed using
        // `ethers_signers::to_eip155_v`.
        sig[64] = src.v.as_u64() as u8;
        sig
    }
}

impl Signature {
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        if data.len() != 65 {
            return Err(anyhow!("Invalid signature length"));
        }

        let v = if data[64] >= 27 {
            U64::from(data[64])
        } else {
            U64::from(data[64] + 27)
        };

        Ok(Signature {
            v,
            r: U256::from_big_endian(&data[0..32]),
            s: U256::from_big_endian(&data[32..64]),
        })
    }

    pub fn recover_public_key(&self, hash: &[u8]) -> Result<PublicKey> {
        let message = Message::from_slice(hash)?;
        let recovery_id = RecoveryId::from_i32(self.v.as_u32() as i32 - 27)?;
        let sig = <[u8; 65]>::from(self);
        let signature = RecoverableSignature::from_compact(&sig[0..64], recovery_id)?;

        Ok(SECP256K1_ENGINE.recover_ecdsa(&message, &signature)?)
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Transaction {
    pub to: Address,
    pub nonce: U64,
    pub gas: U256,
    pub gas_price: U256,
    pub value: U256,
    pub data: Vec<u8>,
    pub access_list: AccessList,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub chain_id: U64,
    pub transaction_type: TransactionType,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SignedTransaction {
    pub transaction: Transaction,
    pub signature: Signature,
}

impl SignedTransaction {
    pub fn hash(&self) -> H256 {
        H256::from(keccak256(self.raw().as_slice()))
    }

    pub fn raw(&self) -> Vec<u8> {
        self.transaction.encode(Some(&self.signature))
    }
}

impl Transaction {
    fn rlp_append_legacy(&self, stream: &mut RlpStream) {
        stream.append(&self.nonce);
        stream.append(&self.gas_price);
        stream.append(&self.gas);
        stream.append(&self.to);
        stream.append(&self.value);
        stream.append(&self.data);
    }

    fn encode_legacy(&self, signature: Option<&Signature>) -> RlpStream {
        let mut stream = RlpStream::new();

        stream.begin_list(9);

        self.rlp_append_legacy(&mut stream);

        if let Some(signature) = signature {
            self.rlp_append_signature(&mut stream, signature);
        } else {
            stream.append(&self.chain_id);
            stream.append(&0u8);
            stream.append(&0u8);
        }

        stream
    }

    fn encode_eip2930_payload(&self, signature: Option<&Signature>) -> RlpStream {
        let mut stream = RlpStream::new();

        let list_size = if signature.is_some() { 11 } else { 8 };
        stream.begin_list(list_size);

        // append chain_id. from EIP-2930: chainId is defined to be an integer of arbitrary size.
        stream.append(&self.chain_id);

        self.rlp_append_legacy(&mut stream);
        self.rlp_append_access_list(&mut stream);

        if let Some(signature) = signature {
            self.rlp_append_signature(&mut stream, signature);
        }

        stream
    }

    fn encode_eip1559_payload(&self, signature: Option<&Signature>) -> RlpStream {
        let mut stream = RlpStream::new();

        let list_size = if signature.is_some() { 12 } else { 9 };
        stream.begin_list(list_size);

        stream.append(&self.chain_id);

        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas);
        stream.append(&self.to);
        stream.append(&self.value);
        stream.append(&self.data);

        self.rlp_append_access_list(&mut stream);

        if let Some(signature) = signature {
            self.rlp_append_signature(&mut stream, signature);
        }

        stream
    }

    fn rlp_append_signature(&self, stream: &mut RlpStream, signature: &Signature) {
        match self.transaction_type {
            TransactionType::Eip2930 | TransactionType::Eip1559 => {
                stream.append(&U64::from(signature.v.as_u64() - 27))
            }
            _ => stream.append(&to_eip155_v(signature.v.as_u64() - 27, self.chain_id)),
        };

        stream.append(&signature.r);
        stream.append(&signature.s);
    }

    fn rlp_append_access_list(&self, stream: &mut RlpStream) {
        stream.begin_list(self.access_list.len());
        for access in self.access_list.iter() {
            stream.begin_list(2);
            stream.append(&access.address);
            stream.begin_list(access.storage_keys.len());
            for storage_key in access.storage_keys.iter() {
                stream.append(storage_key);
            }
        }
    }

    pub fn encode(&self, signature: Option<&Signature>) -> Vec<u8> {
        match self.transaction_type {
            TransactionType::Legacy => {
                let stream = self.encode_legacy(signature);
                stream.out().to_vec()
            }

            TransactionType::Eip2930 => {
                let stream = self.encode_eip2930_payload(signature);
                [&[1], stream.as_raw()].concat()
            }

            TransactionType::Eip1559 => {
                let stream = self.encode_eip1559_payload(signature);
                [&[2], stream.as_raw()].concat()
            }
        }
    }

    pub fn sighash(&self) -> Hash256 {
        keccak256(&self.encode(None))
    }

    pub fn to_signed_tx(&self, signature: Signature) -> SignedTransaction {
        SignedTransaction {
            transaction: self.clone(),
            signature,
        }
    }
}

#[cfg(test)]
mod test {
    use super::{Signature, SignedTransaction, Transaction, TransactionType};
    use crate::transaction_types::AccessListItem;
    use ethereum_types::{Address, H160, H256, U256, U64};
    use std::str::FromStr;
    use tcx_common::ToHex;

    fn test_encode_transaction() {
        let inputs = vec![
            "f8ac826b4685152b17381683015f90946149c26cd2f7b5ccdb32029af817123f6e37df5b80b844a9059cbb0000000000000000000000004bc7610cc68c1647a3898273fd5c6fada35231ec000000000000000000000000000000000000000000000016a8ea51575148000025a0cf11204d960208f37e5cbb1f77c65868e94fcd7d1b6e1a4024c3de2ff038fbd6a04355c8fc835261d4a31b0195af79dfc6a24e3c1e8efb540144618c36f2c9b61a",
            "02f875018321ad6f847735940085266ac4320082520894526ea8b99ba85ec6d883b06545f4b76b60ffe14d879790f8dbf7100080c080a06126c506f0f6b35eca2087e8eb05287d98ccde7fb29499338c70e836538ec212a067eaf101982fb70eb15074c7e58807dac1c725bb33871801d769019efbb0721c",
            "01f902b801820486854671ef231a8307a120947da08ac2740268f36634c2579739be26a123595880b8e4a4629a100000000000000000000000006d7b6dad6abed1dfa5eba37a6667ba9dcfd49077000000000000000000000000132eeb05d5cb6829bd34f552cde0b6b708ef501400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000003da7cd5f6614bd440000000000000000000000000000000000000000000000456a8e21f079c20b8c0000000000000000000000000000000000000000000000003e39a04969da8e6e0000000000000000000000000000000000000000000000000000000000c8913df90168d6941b40183efb4dd766f11bda7a7c3ad8982e998421c0d694c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2c0f89b946d7b6dad6abed1dfa5eba37a6667ba9dcfd49077f884a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000008a0000000000000000000000000000000000000000000000000000000000000000cf89b94132eeb05d5cb6829bd34f552cde0b6b708ef5014f884a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000008a0000000000000000000000000000000000000000000000000000000000000000c80a0e8f03759dc73deaf10ceabc76e206b3a3353a19cbc908ba87c34e5f1d4dc7ef9a0681de4e59147a73ec88422fe9266a7f263c86c4c809e9179a5431fdd5cbe68b4",
            "f8a8808503dea3b69c82d03294dac17f958d2ee523a2206206994597c13d831ec780b844095ea7b30000000000000000000000008a42d311d282bfcaa5133b2de0a8bcdbecea3073ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff269f5327baacf5a3ae6523c6e6ebaa0cd8f98a8ac513c1baed06ec4811b1cfd979a04e4a4714104d70a6f6b91e80846ff8864aa5343e3afcd9ec59683fb011059cfb"];
        let hashs = vec![
            "83ab13113196831454d55ace3a3975da33ec0dc7126767c420258df11407df89",
            "a44c3f4b6fd573f1b5585e6fb9624eb589537f03c25461828767c7b3d56fbb3f",
            "e19e246e305b2c092e77028777a86144c5fc3f56d41c4bdfcc32ce2438993358",
            "885525dbd0a74e58570a0e96a851225cb8f5c690c49b554d9a69c79389ac0374",
        ];
        let signed_transactions = vec![
            SignedTransaction {
                transaction: Transaction {
                    to: Address::from_str("6149c26cd2f7b5ccdb32029af817123f6e37df5b").unwrap(),
                    nonce: U64::from(0x6b46),
                    gas: U256::from_str("15f90").unwrap(),
                    gas_price: U256::from_str("152b173816").unwrap(),
                    value: U256::from_str("00").unwrap(),
                    data: hex::decode("a9059cbb0000000000000000000000004bc7610cc68c1647a3898273fd5c6fada35231ec000000000000000000000000000000000000000000000016a8ea515751480000").unwrap(),
                    transaction_type: TransactionType::Legacy,
                    access_list: vec![],
                    max_priority_fee_per_gas: U256::from_str("00").unwrap(),
                    max_fee_per_gas: U256::from_str("00").unwrap(),
                    chain_id: U64::from(1),
                },
                signature: Signature {
                    v: U64::from(0x25+27),
                    r: U256::from_str("cf11204d960208f37e5cbb1f77c65868e94fcd7d1b6e1a4024c3de2ff038fbd6").unwrap(),
                    s: U256::from_str("4355c8fc835261d4a31b0195af79dfc6a24e3c1e8efb540144618c36f2c9b61a").unwrap(),
                },
            },
            SignedTransaction {
                transaction: Transaction {
                    gas: U256::from_str("5208").unwrap(),
                    gas_price: U256::from_str("266ac43200").unwrap(),
                    max_fee_per_gas: U256::from_str("266ac43200").unwrap(),
                    max_priority_fee_per_gas: U256::from_str("77359400").unwrap(),
                    data: vec![],
                    nonce: U64::from(0x21ad6f),
                    value: U256::from_str("9790f8dbf71000").unwrap(),
                    to: Address::from_str("526ea8b99ba85ec6d883b06545f4b76b60ffe14d").unwrap(),
                    transaction_type: TransactionType::Eip1559,
                    access_list: vec![],
                    chain_id: U64::from(1),
                },
                signature: Signature {
                    v: U64::from(0x0+27),
                    r: U256::from_str("6126c506f0f6b35eca2087e8eb05287d98ccde7fb29499338c70e836538ec212").unwrap(),
                    s: U256::from_str("67eaf101982fb70eb15074c7e58807dac1c725bb33871801d769019efbb0721c").unwrap(),
                },
            },
            SignedTransaction {
                transaction: Transaction {
                    to: Address::from_str("7da08ac2740268f36634c2579739be26a1235958").unwrap(),
                    nonce: U64::from(0x486),
                    gas: U256::from_str("7a120").unwrap(),
                    gas_price: U256::from_str("4671ef231a").unwrap(),
                    max_fee_per_gas: U256::from_str("4671ef231a").unwrap(),
                    value: U256::from_str("0").unwrap(),
                    data: hex::decode("a4629a100000000000000000000000006d7b6dad6abed1dfa5eba37a6667ba9dcfd49077000000000000000000000000132eeb05d5cb6829bd34f552cde0b6b708ef501400000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000003da7cd5f6614bd440000000000000000000000000000000000000000000000456a8e21f079c20b8c0000000000000000000000000000000000000000000000003e39a04969da8e6e0000000000000000000000000000000000000000000000000000000000c8913d").unwrap(),
                    transaction_type: TransactionType::Eip2930,
                    access_list: vec![
                        AccessListItem {
                            address: H160::from_str("1b40183efb4dd766f11bda7a7c3ad8982e998421").unwrap(),
                            storage_keys: vec![],
                        },
                        AccessListItem {
                            address: H160::from_str("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(),
                            storage_keys: vec![]
                        },
                        AccessListItem {
                            address: H160::from_str("6d7b6dad6abed1dfa5eba37a6667ba9dcfd49077").unwrap(),
                            storage_keys: vec![
                                H256::from_str("0000000000000000000000000000000000000000000000000000000000000006").unwrap(),
                                H256::from_str("0000000000000000000000000000000000000000000000000000000000000007").unwrap(),
                                H256::from_str("0000000000000000000000000000000000000000000000000000000000000008").unwrap(),
                                H256::from_str("000000000000000000000000000000000000000000000000000000000000000c").unwrap(),
                            ],
                        },
                        AccessListItem {
                            address: H160::from_str("132eeb05d5cb6829bd34f552cde0b6b708ef5014").unwrap(),
                            storage_keys: vec![
                                H256::from_str("0000000000000000000000000000000000000000000000000000000000000006").unwrap(),
                                H256::from_str("0000000000000000000000000000000000000000000000000000000000000007").unwrap(),
                                H256::from_str("0000000000000000000000000000000000000000000000000000000000000008").unwrap(),
                                H256::from_str("000000000000000000000000000000000000000000000000000000000000000c").unwrap(),
                            ]
                        }
                    ],
                    max_priority_fee_per_gas: U256::from_str("0").unwrap(),
                    chain_id: U64::from(1),
                },
                signature: Signature {
                    v: U64::from(0x0 + 27),
                    r: U256::from_str("e8f03759dc73deaf10ceabc76e206b3a3353a19cbc908ba87c34e5f1d4dc7ef9").unwrap(),
                    s: U256::from_str("681de4e59147a73ec88422fe9266a7f263c86c4c809e9179a5431fdd5cbe68b4").unwrap(),
                },
            },
            SignedTransaction {
                transaction: Transaction {
                    gas: U256::from_str("d032").unwrap(),
                    gas_price: U256::from_str("03dea3b69c").unwrap(),
                    max_fee_per_gas: U256::from_str("03dea3b69c").unwrap(),
                    max_priority_fee_per_gas: U256::from_str("0").unwrap(),
                    data: hex::decode("095ea7b30000000000000000000000008a42d311d282bfcaa5133b2de0a8bcdbecea3073ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap(),
                    nonce: U64::from(0x0),
                    value: U256::from_str("0").unwrap(),
                    to: Address::from_str("dac17f958d2ee523a2206206994597c13d831ec7").unwrap(),
                    transaction_type: TransactionType::Legacy,
                    access_list: vec![],
                    chain_id: U64::from(1),
                },
                signature: Signature {
                    v: U64::from(38),
                    r: U256::from_str("5327baacf5a3ae6523c6e6ebaa0cd8f98a8ac513c1baed06ec4811b1cfd979").unwrap(),
                    s: U256::from_str("4e4a4714104d70a6f6b91e80846ff8864aa5343e3afcd9ec59683fb011059cfb").unwrap(),
                },
            },
            ];

        for i in 0..inputs.len() {
            assert_eq!(signed_transactions[i].raw().to_hex(), inputs[i],);
            assert_eq!(signed_transactions[i].hash().to_hex(), hashs[i],);
        }
    }
}
