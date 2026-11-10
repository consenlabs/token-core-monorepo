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
        if (this.selected !== 'isd') throw new Error('interleaved SELECT');
        return 'ABCD9000';
      }
      throw new Error('unexpected APDU ' + apdu);
    }
  };
}

export function sessionTrace(mock) { return mock.calls.join(','); }
")]
extern "C" {
    #[wasm_bindgen(js_name = sessionMock)]
    fn session_mock(public_key: &str) -> JsValue;
    #[wasm_bindgen(js_name = sessionTrace)]
    fn session_trace(mock: &JsValue) -> String;
}

#[wasm_bindgen_test]
async fn public_sign_and_seid_are_atomic_and_recover_after_failure() {
    let public_key = concat!(
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );
    let mock = session_mock(public_key);
    set_transport(mock.clone());
    let old_key = std::mem::replace(
        &mut ikc_device::device_binding::KEY_MANAGER.lock().pri_key,
        vec![1; 32],
    );
    let sender = EthAddress::from_pub_key(hex::decode(public_key).unwrap()).unwrap();
    let params = serde_json::json!({
        "chainType": "ETHEREUM", "path": "m/44'/60'/0'/0/0", "sender": sender,
        "input": { "message": "hello", "isPersonalSign": true }
    })
    .to_string();
    let (signed, seid) = futures_util::join!(sign_message(&params), get_seid());
    assert!(
        js_value_message(&signed.unwrap_err(), "missing error").contains("mock_prepare_failure")
    );
    assert_eq!(seid.unwrap(), "ABCD");
    let trace = session_trace(&mock);
    let commands: Vec<_> = trace.split(',').collect();
    assert_eq!(commands.len(), 5, "{trace}");
    assert!(commands[0].starts_with("00A4"));
    assert!(commands[1].starts_with("8053"));
    assert!(commands[2].starts_with("8054"));
    assert!(commands[3].starts_with("00A4"));
    assert_eq!(commands[4], "80CB800005DFFF028101");
    assert_eq!(get_seid().await.unwrap(), "ABCD");
    ikc_device::device_binding::KEY_MANAGER.lock().pri_key = old_key;
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
