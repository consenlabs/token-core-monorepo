use super::*;
use wasm_bindgen_test::wasm_bindgen_test;

#[cfg(feature = "browser-tests")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen(inline_js = "
export function sessionMock(publicKey) {
  return {
    calls: [], selected: '',
    async sendApduRaw(apdu) {
      apdu = apdu.toUpperCase();
      this.calls.push(apdu);
      await Promise.resolve();
      if (apdu.startsWith('00A4')) {
        this.selected = apdu.includes('695F657468'.toUpperCase()) ? 'sign' : 'isd';
        return '9000';
      }
      if (apdu.startsWith('8053')) {
        if (this.selected !== 'sign') throw new Error('interleaved SELECT');
        return publicKey + '9000';
      }
      if (apdu.startsWith('8054')) {
        if (this.selected !== 'sign') throw new Error('interleaved SELECT');
        throw new Error('mock_prepare_failure');
      }
      if (apdu === '80CB800005DFFF028101') {
        if (this.failBind) throw new Error('mock_bind_failure');
        if (this.selected !== 'isd') throw new Error('interleaved SELECT');
        return 'ABCD9000';
      }
      if (apdu === '80CA004400') return '6D6F636B9000';
      if (apdu.startsWith('8071')) return '559000';
      if (apdu.startsWith('8043')) return publicKey + '01'.repeat(32) + '9000';
      if (apdu.startsWith('8037')) return '9000';
      throw new Error('unexpected APDU ' + apdu);
    }
  };
}

export function sessionTrace(mock) { return mock.calls.join(','); }
export function resetTrace(mock) { mock.calls = []; }
export function failBind(mock) { mock.failBind = true; }
export function bindingStorage(value) { return { async getBindKey() { return value; } }; }
")]
extern "C" {
    #[wasm_bindgen(js_name = sessionMock)]
    fn session_mock(public_key: &str) -> JsValue;
    #[wasm_bindgen(js_name = sessionTrace)]
    fn session_trace(mock: &JsValue) -> String;
    #[wasm_bindgen(js_name = resetTrace)]
    fn reset_trace(mock: &JsValue);
    #[wasm_bindgen(js_name = failBind)]
    fn fail_bind(mock: &JsValue);
    #[wasm_bindgen(js_name = bindingStorage)]
    fn mock_binding_storage(value: &str) -> JsValue;
}

const PUBLIC_KEY: &str = concat!(
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
);

struct Client {
    binding: ImKeyBindingContext,
    transport: JsValue,
    storage: JsValue,
}

impl Client {
    fn new(key_byte: u8) -> Self {
        let mut keys = KeyManager::new();
        keys.gen_encrypt_key("ABCD", "mock");
        keys.pri_key = vec![key_byte; 32];
        let secret = bitcoin::secp256k1::SecretKey::from_slice(&keys.pri_key).unwrap();
        keys.pub_key = bitcoin::secp256k1::PublicKey::from_secret_key(
            &bitcoin::secp256k1::Secp256k1::new(),
            &secret,
        )
        .serialize_uncompressed()
        .to_vec();
        keys.se_pub_key = hex::decode(PUBLIC_KEY).unwrap();
        keys.session_key = vec![key_byte; 16];
        Self {
            binding: ImKeyBindingContext::new(),
            transport: session_mock(PUBLIC_KEY),
            storage: mock_binding_storage(&keys.encrypt_data().unwrap()),
        }
    }

    fn select(&self) {
        set_binding_context(&self.binding);
        set_transport(self.transport.clone());
        set_binding_storage(self.storage.clone());
    }

    async fn bind(&self) {
        self.select();
        assert_eq!(bind_check().await.unwrap(), "bound_this");
        assert!(KEY_MANAGER.lock().pri_key.is_empty());
        reset_trace(&self.transport);
    }
}

fn sign_params() -> String {
    let sender = EthAddress::from_pub_key(hex::decode(PUBLIC_KEY).unwrap()).unwrap();
    serde_json::json!({
        "chainType": "ETHEREUM", "path": "m/44'/60'/0'/0/0", "sender": sender,
        "input": { "message": "hello", "isPersonalSign": true }
    })
    .to_string()
}

async fn auth_signature(client: &Client, key_byte: u8) -> String {
    client.select();
    reset_trace(&client.transport);
    let error = sign_message(&sign_params()).await.unwrap_err();
    assert!(js_value_message(&error, "missing error").contains("mock_prepare_failure"));
    let trace = session_trace(&client.transport);
    let prepare = trace
        .split(',')
        .find(|apdu| apdu.starts_with("8054"))
        .unwrap();
    let apdu = hex::decode(prepare).unwrap();
    let signature_length = apdu[6] as usize;
    let signature = &apdu[7..7 + signature_length];
    let expected = ikc_common::utility::secp256k1_sign(
        &[key_byte; 32],
        &apdu[7 + signature_length..apdu.len() - 1],
    )
    .unwrap();
    assert_eq!(signature, expected);
    assert!(KEY_MANAGER.lock().pri_key.is_empty());
    hex::encode(signature)
}

#[wasm_bindgen_test]
async fn public_sign_and_seid_are_atomic_and_recover_after_failure() {
    let client = Client::new(1);
    client.bind().await;
    let mock = &client.transport;
    let params = sign_params();
    let (signed, seid) = futures_util::join!(sign_message(&params), get_seid());
    assert!(
        js_value_message(&signed.unwrap_err(), "missing error").contains("mock_prepare_failure")
    );
    assert_eq!(seid.unwrap(), "ABCD");
    let trace = session_trace(mock);
    let commands: Vec<_> = trace.split(',').collect();
    assert_eq!(commands.len(), 5, "{trace}");
    assert!(commands[0].starts_with("00A4"));
    assert!(commands[1].starts_with("8053"));
    assert!(commands[2].starts_with("8054"));
    assert!(commands[3].starts_with("00A4"));
    assert_eq!(commands[4], "80CB800005DFFF028101");
    assert_eq!(get_seid().await.unwrap(), "ABCD");
    clear_transport();
}

#[wasm_bindgen_test]
async fn queued_session_keeps_its_transport_snapshot() {
    let first = session_mock("");
    let second = session_mock("");
    set_transport(first.clone());
    let first_operation = get_seid();
    let switch = async {
        set_transport(second.clone());
        get_seid().await
    };
    let (a, b) = futures_util::join!(first_operation, switch);
    assert_eq!(a.unwrap(), "ABCD");
    assert_eq!(b.unwrap(), "ABCD");
    assert_eq!(session_trace(&first).split(',').count(), 2);
    assert_eq!(session_trace(&second).split(',').count(), 2);
    clear_transport();
}

#[wasm_bindgen_test]
async fn binding_keys_follow_clients_a_b_a_and_unbound_clients_fail_closed() {
    let a = Client::new(1);
    let b = Client::new(2);
    a.bind().await;
    let first_a = auth_signature(&a, 1).await;

    b.select();
    let before = session_trace(&b.transport);
    for error in [
        sign_message(&sign_params()).await.unwrap_err(),
        sign_tx(&sign_params()).await.unwrap_err(),
        sign_psbt(&sign_params()).await.unwrap_err(),
        bind_acquire("ABCDEFGH").await.unwrap_err(),
        get_address(r#"{"chainType":"TRON","path":"m/44'/195'/0'/0/0"}"#)
            .await
            .unwrap_err(),
    ] {
        assert_eq!(error.as_string().unwrap(), "imkey_bind_check_required");
    }
    assert_eq!(session_trace(&b.transport), before);
    b.bind().await;
    let signed_b = auth_signature(&b, 2).await;
    assert_ne!(first_a, signed_b);
    assert_eq!(auth_signature(&a, 1).await, first_a);
    clear_transport();
}

#[wasm_bindgen_test]
async fn failed_bind_and_changed_transport_or_storage_do_not_reuse_keys() {
    let a = Client::new(1);
    let b = Client::new(2);
    a.bind().await;
    b.bind().await;
    a.select();
    fail_bind(&a.transport);
    assert!(bind_check().await.is_err());
    assert_eq!(
        sign_message(&sign_params())
            .await
            .unwrap_err()
            .as_string()
            .unwrap(),
        "imkey_bind_check_required"
    );
    auth_signature(&b, 2).await;

    for change_storage in [true, false] {
        b.bind().await;
        if change_storage {
            set_binding_storage(a.storage.clone());
        } else {
            set_transport(a.transport.clone());
        }
        assert_eq!(
            sign_message(&sign_params())
                .await
                .unwrap_err()
                .as_string()
                .unwrap(),
            "imkey_bind_check_required"
        );
    }
    b.bind().await;
    b.binding.clear();
    assert_eq!(
        sign_message(&sign_params())
            .await
            .unwrap_err()
            .as_string()
            .unwrap(),
        "imkey_bind_check_required"
    );
    clear_transport();
}

#[wasm_bindgen_test]
async fn queued_signing_keeps_both_binding_and_transport_snapshots() {
    let a = Client::new(1);
    let b = Client::new(2);
    a.bind().await;
    b.bind().await;
    a.select();
    let params = sign_params();
    let first = sign_message(&params);
    let switch = async {
        b.select();
        sign_message(&params).await
    };
    let (first, second) = futures_util::join!(first, switch);
    for result in [first, second] {
        assert!(js_value_message(&result.unwrap_err(), "missing error")
            .contains("mock_prepare_failure"));
    }
    assert!(session_trace(&a.transport).contains("8054"));
    assert!(session_trace(&b.transport).contains("8054"));
    auth_signature(&a, 1).await;
    auth_signature(&b, 2).await;
    clear_transport();
}

#[wasm_bindgen_test]
async fn ltc_native_segwit_aliases_agree_for_address_registration_and_sub_accounts() {
    let client = Client::new(1);
    client.select();
    let mut expected = None;
    for mode in ["SEGWIT", "VERSION_0", "segwit", "version_0"] {
        let params = serde_json::json!({
            "chainType": "LITECOIN", "path": "m/84'/2'/0'/0/0", "network": "MAINNET",
            "segWit": mode,
        })
        .to_string();
        let address: serde_json::Value =
            serde_json::from_str(&get_address(&params).await.unwrap()).unwrap();
        let registered: serde_json::Value =
            serde_json::from_str(&register_address(&params).await.unwrap()).unwrap();
        assert_eq!(address["address"], registered["address"]);
        assert!(address["address"].as_str().unwrap().starts_with("ltc1"));
        if let Some(expected) = &expected {
            assert_eq!(&address["address"], expected);
        } else {
            expected = Some(address["address"].clone());
        }

        let params = serde_json::json!({
            "chainType": "LITECOIN", "curve": "secp256k1", "network": "MAINNET", "segWit": mode,
            "relativePaths": ["0/0"],
            "extendedPublicKey": "xpub6Gxe3rj6UCkx1oZSg36MnEtVcj6utTcuY2tHeyEgpXEnm9Hde8AVQrUHPnYS5mhRp4ML7GgeMCVgdpWE3gfN5hG4ayRUrF4e5UPuKEwzpns",
        }).to_string();
        let accounts: serde_json::Value =
            serde_json::from_str(&derive_sub_accounts(&params).await.unwrap()).unwrap();
        assert!(accounts["accounts"][0]["address"]
            .as_str()
            .unwrap()
            .starts_with("ltc1"));
    }
    clear_transport();
}
