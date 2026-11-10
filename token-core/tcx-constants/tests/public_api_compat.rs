use tcx_constants::curve::CurveType;

#[test]
fn legacy_curve_module_and_root_export_are_identical() {
    let curve: tcx_constants::CurveType = CurveType::ED25519;
    assert_eq!(curve.as_str(), "ed25519");
    assert_eq!(CurveType::from_str("secp256k1"), CurveType::SECP256k1);
}
