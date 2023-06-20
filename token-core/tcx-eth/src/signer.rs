use crate::transaction::{EthTxInput, EthTxOutput};
use crate::types::Action;
use crate::Result;
use ethereum_types::{Address, H256, U256, U64};
use ethers::abi::AbiEncode;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::transaction::eip2930::{AccessList, AccessListItem};
use ethers::types::{
    Bytes, Eip1559TransactionRequest, NameOrAddress, Signature, TransactionRequest,
};
use failure::format_err;
use hex::ToHex;
use keccak_hash::keccak;
use rlp::{self, DecoderError, Encodable, Rlp, RlpStream};
use std::hash::Hash;
use std::str::FromStr;
use tcx_common::utility::hex_to_bytes;
use tcx_wallet::imt_keystore::IMTKeystore;
use tcx_wallet::wallet_manager::WalletManager;
use tiny_keccak::Hasher;

impl EthTxInput {
    pub async fn sign(&self, private_key: &[u8]) -> Result<EthTxOutput> {
        // let wallet = "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6"
        //     .parse::<LocalWallet>()?;
        let wallet = LocalWallet::from_bytes(private_key)?;
        let ret_result = if self.tx_type.to_lowercase() == "0x02"
            || self.tx_type.to_lowercase() == "0x2"
            || self.tx_type == "02"
        {
            let mut eip1559_tx = Eip1559TransactionRequest::new()
                .nonce(U256::from_dec_str(&self.nonce)?)
                .to(self.to.parse::<Address>()?)
                .value(U256::from_dec_str(&self.value)?)
                .gas(U256::from_dec_str(&self.gas_limit)?)
                .data(Bytes::from_str(&self.data)?)
                .chain_id(U64::from_dec_str(&self.chain_id)?)
                .max_priority_fee_per_gas(U256::from_dec_str(&self.max_priority_fee_per_gas)?)
                .max_fee_per_gas(U256::from_dec_str(&self.max_fee_per_gas)?)
                .access_list(self.parse_access_list_item()?);
            let hash: H256 = TypedTransaction::Eip1559(eip1559_tx.clone()).sighash();
            println!("sign hash-->{}", hex::encode(hash.as_ref()));
            let signature = wallet
                .sign_transaction(&TypedTransaction::Eip1559(eip1559_tx.clone()))
                .await?;
            println!("signdata-->{}", hex::encode(signature.s.encode()));
            let sign_result = eip1559_tx.rlp_signed(&signature);
            let mut sign_bytes = vec![];
            sign_bytes.push(self.tx_type.parse()?);
            sign_bytes.extend(sign_result.as_ref().iter());
            let signature = hex::encode(sign_bytes.clone());
            println!("signature result -->{}", signature.clone());
            let tx_hash = format!("{}{}", "0x", hex::encode(keccak(sign_bytes).as_ref()));
            println!("tx_hash-->{}", tx_hash);
            EthTxOutput { signature, tx_hash }
        } else {
            let legacy_tx = TransactionRequest::new()
                .nonce(U256::from_dec_str(&self.nonce)?)
                .to(self.to.parse::<Address>()?)
                .value(U256::from_dec_str(&self.value)?)
                .gas_price(U256::from_dec_str(&self.gas_price)?)
                .gas(U256::from_dec_str(&self.gas_limit)?)
                .data(Bytes::from_str(&self.data)?)
                .chain_id(U64::from_dec_str(&self.chain_id)?);

            let sign_hash: H256 = TypedTransaction::Legacy(legacy_tx.clone()).sighash();
            println!("sign hash-->{}", hex::encode(sign_hash.as_ref()));
            let signature = wallet
                .sign_transaction(&TypedTransaction::Legacy(legacy_tx.clone()))
                .await?;
            println!("signdata-->{}", hex::encode(signature.s.encode()));
            let sign_result = legacy_tx.rlp_signed(&signature);
            let signature = hex::encode(sign_result.clone());
            println!("signature result -->{}", signature.clone());
            let tx_hash = format!(
                "{}{}",
                "0x",
                hex::encode(keccak(sign_result.as_ref()).as_ref())
            );
            println!("tx_hash-->{}", tx_hash);
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
            let mut item = AccessListItem {
                address: ethereum_types::Address::from_str(&access.address)?,
                storage_keys: {
                    let mut storage_keys: Vec<H256> = Vec::new();
                    for key in &access.storage_keys {
                        let key_bytes: [u8; 32] = hex_to_bytes(key.as_str())?.try_into().unwrap();
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

#[cfg(test)]
mod test {
    use crate::transaction::{AccessList, EthTxInput};
    use async_std::task;
    use ethers::types::U256;
    use tcx_wallet::imt_keystore::IMTKeystore;

    #[test]
    fn test_tx() {
        // let tx = EthTxInput{
        //     nonce: "33738".to_string(),
        //     gas_price: "5000000000".to_string(),
        //     gas_limit: "50000".to_string(),
        //     to: "0x6031564e7b2f5cc33737807b2e58daff870b590b".to_string(),
        //     value: "607001513671985".to_string(),
        //     data: "".to_string(),
        //     chain_id: "42".to_string(),
        //     tx_type: "01".to_string(),
        //     max_fee_per_gas: "2000000000".to_string(),
        //     max_priority_fee_per_gas: "2000000000".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let tx = EthTxInput{
        //     nonce: "549".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "21000".to_string(),
        //     to: "0x03e2B0f5369297a2E7A13d6F8e6d4BFbB9cf7dC7".to_string(),
        //     value: "500000000000000".to_string(),
        //     data: "".to_string(),
        //     chain_id: "42".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "2000000000".to_string(),
        //     max_priority_fee_per_gas: "2000000000".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let tx = EthTxInput{
        //     nonce: "548".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "220".to_string(),
        //     to: "0x87e65b8280098da8f9bb3a69643573378da87542".to_string(),
        //     value: "44902".to_string(),
        //     data: "0x3400711e1d0bfbcf".to_string(),
        //     chain_id: "42".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "2298206284".to_string(),
        //     max_priority_fee_per_gas: "163".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let tx = EthTxInput{
        //     nonce: "8".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "14298499".to_string(),
        //     to: "0xef970655297d1234174bcfe31ee803aaa97ad0ca".to_string(),
        //     value: "11".to_string(),
        //     data: "0xee".to_string(),
        //     chain_id: "130".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "850895266216".to_string(),
        //     max_priority_fee_per_gas: "69".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let mut access_list = vec![];
        //
        // access_list.push(AccessList{
        //     address: "0x70b361fc3a4001e4f8e4e946700272b51fe4f0c4".to_string(),
        //     storage_keys: vec!["0x8419643489566e30b68ce5bc642e166f86e844454c99a03ed4a3d4a2b9a96f63".to_string(),
        //                        "0x8a2a020581b8f3142a9751344796fb1681a8cde503b6662d43b8333f863fb4d3".to_string(),
        //                        "0x897544db13bf6cd166ce52498d894fe6ce5a8d2096269628e7f971e818bf9ab9".to_string()]
        // });
        // let tx = EthTxInput{
        //     nonce: "4".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "54".to_string(),
        //     to: "0xd5539a0e4d27ebf74515fc4acb38adcc3c513f25".to_string(),
        //     value: "64".to_string(),
        //     data: "0xf579eebd8a5295c6f9c86e".to_string(),
        //     chain_id: "276".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "963240322143".to_string(),
        //     max_priority_fee_per_gas: "28710".to_string(),
        //     access_list,
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let mut access_list= vec![];
        // access_list.push(AccessList{
        //     address: "0x55a7ce45514b6e71743bbb67e9959bd19eefb8ed".to_string(),
        //     storage_keys: vec!["0x766d2c1aef5f615a3f935de247800dfbf9a8bb7be5a43795f78f9c83f24f013d".to_string(),
        //                        "0xb34339a846e7a304ad82e20b3cf05260698566efc1c6488bf851689a279d262e".to_string()]
        // });
        // let tx = EthTxInput{
        //     nonce: "6".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "10884139".to_string(),
        //     to: "0xd24911709fa01130804188b5c76ed65bfdfd6a05".to_string(),
        //     value: "4990".to_string(),
        //     data: "0xe9290f2d3d754ba522".to_string(),
        //     chain_id: "225".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "2984486799".to_string(),
        //     max_priority_fee_per_gas: "183".to_string(),
        //     access_list,
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let mut access_list= vec![];
        // access_list.push(AccessList{
        //     address: "0x4824aec0a347a627d2bd88ae1f69a41b0665fed0".to_string(),
        //     storage_keys: vec![]
        // });
        // let tx = EthTxInput{
        //     nonce: "3".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "41708".to_string(),
        //     to: "0xaf9031dff5db0a02d25cd09b3cbb0d3f7f332faf".to_string(),
        //     value: "44939".to_string(),
        //     data: "0x4f".to_string(),
        //     chain_id: "365".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "259340687386".to_string(),
        //     max_priority_fee_per_gas: "223".to_string(),
        //     access_list,
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let mut access_list= vec![];
        // access_list.push(AccessList{
        //     address: "0x019fda53b3198867b8aae65320c9c55d74de1938".to_string(),
        //     storage_keys: vec![]
        // });
        // access_list.push(AccessList{
        //     address: "0x1b976cdbc43cfcbeaad2623c95523981ea1e664a".to_string(),
        //     storage_keys: vec!["0xd259410e74fa5c0227f688cc1f79b4d2bee3e9b7342c4c61342e8906a63406a2".to_string()]
        // });
        // access_list.push(AccessList{
        //     address: "0xf1946eba70f89687d67493d8106f56c90ecba943".to_string(),
        //     storage_keys: vec!["0xb3838dedffc33c62f8abfc590b41717a6dd70c3cab5a6900efae846d9060a2b9".to_string(),
        //     "0x6a6c4d1ab264204fb2cdd7f55307ca3a0040855aa9c4a749a605a02b43374b82".to_string(),
        //     "0x0c38e901d0d95fbf8f05157c68a89393a86aa1e821279e4cce78f827dccb2064".to_string()]
        // });
        // let tx = EthTxInput{
        //     nonce: "1".to_string(),
        //     gas_price: "".to_string(),
        //     gas_limit: "4286".to_string(),
        //     to: "0x6f4ecd70932d65ac08b56db1f4ae2da4391f328e".to_string(),
        //     value: "3490361".to_string(),
        //     data: "0x200184c0486d5f082a27".to_string(),
        //     chain_id: "63".to_string(),
        //     tx_type: "02".to_string(),
        //     max_fee_per_gas: "1076634600920".to_string(),
        //     max_priority_fee_per_gas: "226".to_string(),
        //     access_list,
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let tx = EthTxInput{
        //     nonce: "8".to_string(),
        //     gas_price: "20000000008".to_string(),
        //     gas_limit: "189000".to_string(),
        //     to: "0x3535353535353535353535353535353535353535".to_string(),
        //     value: "512".to_string(),
        //     data: "".to_string(),
        //     chain_id: "56".to_string(),
        //     tx_type: "".to_string(),
        //     max_fee_per_gas: "1076634600920".to_string(),
        //     max_priority_fee_per_gas: "226".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let tx = EthTxInput{
        //     nonce: "8".to_string(),
        //     gas_price: "20000000008".to_string(),
        //     gas_limit: "189000".to_string(),
        //     to: "0x3535353535353535353535353535353535353535".to_string(),
        //     value: "512".to_string(),
        //     data: "".to_string(),
        //     chain_id: "1".to_string(),
        //     tx_type: "".to_string(),
        //     max_fee_per_gas: "1076634600920".to_string(),
        //     max_priority_fee_per_gas: "226".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

        // let tx = EthTxInput{
        //     nonce: "8".to_string(),
        //     gas_price: "20000000008".to_string(),
        //     gas_limit: "189000".to_string(),
        //     to: "0x3535353535353535353535353535353535353535".to_string(),
        //     value: "512".to_string(),
        //     data: "".to_string(),
        //     chain_id: "163".to_string(),
        //     tx_type: "".to_string(),
        //     max_fee_per_gas: "1076634600920".to_string(),
        //     max_priority_fee_per_gas: "226".to_string(),
        //     access_list: vec![],
        // };
        // task::block_on(async {
        //     tx.sign( "password").await;
        // });

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
        task::block_on(async {
            tx.sign("password", &IMTKeystore::default()).await;
        });
    }
}
