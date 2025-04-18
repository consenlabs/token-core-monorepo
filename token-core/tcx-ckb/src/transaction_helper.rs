use crate::serializer::Serializer;
use crate::transaction::{Script, Witness};

use super::Error;
use crate::hash::blake2b_256;
use tcx_common::FromHex;
use tcx_keystore::Result;

impl Script {
    pub fn serialize_hash_type(&self) -> Result<Vec<u8>> {
        match self.hash_type.as_str() {
            "data" => Ok(vec![0x00]),
            "type" => Ok(vec![0x01]),
            _ => Err(Error::InvalidHashType.into()),
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let args_bytes = Vec::from_hex_auto(&self.args)?;
        Ok(Serializer::serialize_dynamic_vec(&[
            Vec::from_hex_auto(&self.code_hash)?.as_slice(),
            self.serialize_hash_type()?.as_slice(),
            Serializer::serialize_fixed_vec(vec![args_bytes.as_slice()].as_slice()).as_slice(),
        ]))
    }

    pub fn to_hash(&self) -> Result<Vec<u8>> {
        Ok(blake2b_256(self.serialize()?))
    }
}

impl Witness {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let inner_serialize = |x: &str| -> Result<Vec<u8>> {
            let bytes = Vec::from_hex_auto(x)?;
            if !bytes.is_empty() {
                Ok(Serializer::serialize_fixed_vec(&[bytes.as_slice()]))
            } else {
                Ok(vec![])
            }
        };

        Ok(Serializer::serialize_dynamic_vec(&[
            inner_serialize(&self.lock)?.as_slice(),
            inner_serialize(&self.input_type)?.as_slice(),
            inner_serialize(&self.output_type)?.as_slice(),
        ]))
    }

    fn is_empty(value: &str) -> bool {
        ((value.starts_with("0x") || value.starts_with("0x")) && value.len() == 2)
            || value.len() == 0
    }

    pub fn to_raw(&self) -> Result<Vec<u8>> {
        if Witness::is_empty(&self.lock)
            && Witness::is_empty(&self.input_type)
            && Witness::is_empty(&self.output_type)
        {
            Ok(vec![])
        } else {
            self.serialize()
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::{Script, Witness};
    use crate::Error;
    use tcx_common::{FromHex, ToHex};

    #[test]
    fn serialize_script() {
        let script = Script {
            code_hash: "0x68d5438ac952d2f584abf879527946a537e82c7f3c1cbf6d8ebf9767437d8e88"
                .to_owned(),
            args: "0x3954acece65096bfa81258983ddb83915fc56bd8".to_owned(),
            hash_type: "type".to_string(),
        };

        assert_eq!(script.serialize().unwrap(), Vec::from_hex("4900000010000000300000003100000068d5438ac952d2f584abf879527946a537e82c7f3c1cbf6d8ebf9767437d8e8801140000003954acece65096bfa81258983ddb83915fc56bd8").unwrap());

        let script = Script {
            code_hash: "0x68d5438ac952d2f584abf879527946a537e82c7f3c1cbf6d8ebf9767437d8e88"
                .to_owned(),
            args: "0x".to_owned(),
            hash_type: "type".to_string(),
        };

        assert_eq!(script.serialize().unwrap(), Vec::from_hex("3500000010000000300000003100000068d5438ac952d2f584abf879527946a537e82c7f3c1cbf6d8ebf9767437d8e880100000000").unwrap());
    }

    #[test]
    fn test_invalid_hash_type() {
        let script = Script {
            code_hash: "0x68d5438ac952d2f584abf879527946a537e82c7f3c1cbf6d8ebf9767437d8e88"
                .to_owned(),
            args: "0x3954acece65096bfa81258983ddb83915fc56bd8".to_owned(),
            hash_type: "test".to_string(),
        };
        let actual = script.serialize();

        assert_eq!(
            actual.err().unwrap().to_string(),
            Error::InvalidHashType.to_string()
        );
    }

    #[test]
    fn script_to_hash() {
        let script = Script {
            code_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            args: "0x".to_owned(),
            hash_type: "data".to_string(),
        };

        assert_eq!(
            script.to_hash().unwrap().to_hex(),
            "77c93b0632b5b6c3ef922c5b7cea208fb0a7c427a13d50e13d3fefad17e0c590"
        );

        let script = Script {
            code_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            args: "0x01".to_owned(),
            hash_type: "data".to_string(),
        };
        assert_eq!(
            script.to_hash().unwrap().to_hex(),
            "67951b34bce20cb71b7e235c1f8cda259628d99d94825bffe549c23b4dd2930f"
        );

        let script = Script {
            code_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            args: "0x01".to_owned(),
            hash_type: "type".to_string(),
        };

        assert_eq!(
            script.to_hash().unwrap().to_hex(),
            "d39f84d4702f53cf8625da4411be1640b961715cb36816501798fedb70b6e0fb",
        );
    }

    #[test]
    fn serialize_witness() {
        let witness = Witness {
            lock: "0x".to_owned(),
            input_type: "0x".to_owned(),
            output_type: "0x".to_owned(),
        };

        assert_eq!(
            witness.serialize().unwrap().to_hex(),
            "10000000100000001000000010000000"
        );

        let witness = Witness {
            lock: "0x".to_owned(),
            input_type: "0x10".to_owned(),
            output_type: "0x20".to_owned(),
        };
        assert_eq!(
            witness.serialize().unwrap().to_hex(),
            "1a00000010000000100000001500000001000000100100000020"
        );
    }

    #[test]
    fn witness_to_raw() {
        let witness = Witness {
            lock: "0x".to_owned(),
            input_type: "0x".to_owned(),
            output_type: "0x".to_owned(),
        };
        assert_eq!("", witness.to_raw().unwrap().to_hex());

        let witness = Witness {
            lock: "0x".to_owned(),
            input_type: "0x10".to_owned(),
            output_type: "0x20".to_owned(),
        };
        assert_eq!(
            "1a00000010000000100000001500000001000000100100000020",
            witness.to_raw().unwrap().to_hex()
        );
    }
}
