use serde::{Deserialize, Serialize};
use tcx_constants::CurveType;
use tcx_keystore::Result;

use super::Error;

#[derive(Deserialize, Serialize, Debug)]
pub struct KeyInfo {
    #[serde(rename = "Type")]
    pub r#type: String,

    #[serde(rename = "PrivateKey")]
    pub private_key: String,
}

impl KeyInfo {
    pub fn from_lotus(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice::<KeyInfo>(bytes)?)
    }

    pub fn from_private_key(curve_type: CurveType, private_key: &[u8]) -> Result<Self> {
        match curve_type {
            CurveType::SECP256k1 => Ok(KeyInfo {
                r#type: "secp256k1".to_string(),
                private_key: base64::encode(private_key),
            }),
            CurveType::BLS => Ok(KeyInfo {
                r#type: "bls".to_string(),
                private_key: base64::encode(private_key),
            }),
            _ => Err(Error::InvalidCurveType.into()),
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn decode_private_key(&self) -> Result<Vec<u8>> {
        Ok(base64::decode(&self.private_key)?.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::KeyInfo;
    use tcx_common::{FromHex, ToHex};
    use tcx_constants::CurveType;

    #[test]
    fn test_import_and_export() {
        let raw_private_key = "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a22437544586b6b4b46773549656d55685a545173514369534e6d6a327062545052495439514f736c587846733d227d";
        let key_info = KeyInfo::from_lotus(&Vec::from_hex(raw_private_key).unwrap()).unwrap();
        assert_eq!(key_info.r#type, "secp256k1");
        assert_eq!(
            key_info.decode_private_key().unwrap().to_hex(),
            "0ae0d7924285c3921e9948594d0b100a248d9a3da96d33d1213f503ac957c45b"
        );

        assert_eq!(key_info.to_json().unwrap().to_hex(), raw_private_key);
    }

    #[test]
    fn test_from_private_key_secp256k1() {
        let key_info = KeyInfo::from_private_key(
            CurveType::SECP256k1,
            &Vec::from_hex("0ae0d7924285c3921e9948594d0b100a248d9a3da96d33d1213f503ac957c45b")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(key_info.to_json().unwrap().to_hex(), "7b2254797065223a22736563703235366b31222c22507269766174654b6579223a22437544586b6b4b46773549656d55685a545173514369534e6d6a327062545052495439514f736c587846733d227d");
    }

    #[test]
    fn test_from_private_key_bls() {
        let key_info = KeyInfo::from_private_key(
            CurveType::BLS,
            &Vec::from_hex("0ae0d7924285c3921e9948594d0b100a248d9a3da96d33d1213f503ac957c45b")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(key_info.to_json().unwrap().to_hex(), "7b2254797065223a22626c73222c22507269766174654b6579223a22437544586b6b4b46773549656d55685a545173514369534e6d6a327062545052495439514f736c587846733d227d");
    }

    #[test]
    #[should_panic(expected = "InvalidCurveType")]
    fn test_from_private_key_invalid_curve_type() {
        KeyInfo::from_private_key(
            CurveType::ED25519Blake2bNano,
            &Vec::from_hex("0ae0d7924285c3921e9948594d0b100a248d9a3da96d33d1213f503ac957c45b")
                .unwrap(),
        )
        .unwrap();
    }
}
