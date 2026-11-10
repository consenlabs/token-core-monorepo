use tcx_common::hex::{FromHex, ToHex};

struct LegacyBytes(Vec<u8>);

impl FromHex for LegacyBytes {
    fn from_hex<T: AsRef<[u8]>>(value: T) -> tcx_common::Result<Self> {
        Vec::from_hex(value).map(Self)
    }
}

fn decode_legacy<T: FromHex>(value: &str) -> tcx_common::Result<T> {
    T::from_hex_auto(value)
}

#[test]
fn legacy_module_traits_and_anyhow_result_compile() {
    let bytes: tcx_common::Result<Vec<u8>> = Vec::from_hex("0102");
    assert_eq!(bytes.unwrap().to_0x_hex(), "0x0102");
    assert_eq!(decode_legacy::<LegacyBytes>("0X0102").unwrap().0, [1, 2]);
    assert_eq!(Vec::from_0x_hex("").unwrap(), Vec::<u8>::new());
    assert_eq!(
        Vec::from_hex("zz").unwrap_err().to_string(),
        "Invalid character 'z' at position 0"
    );
    let _: tcx_common::Result<Vec<u8>> = <Vec<u8> as tcx_common::FromHex>::from_hex("00");
    assert_eq!(tcx_common::ToHex::to_hex(&[0u8]), "00");
}
