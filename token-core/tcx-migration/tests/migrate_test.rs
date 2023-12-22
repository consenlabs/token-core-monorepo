use serde_json::Value;
use tcx_crypto::Key;
use tcx_keystore::{Keystore, Source};
use tcx_migration::keystore_upgrade::KeystoreUpgrade;
use tcx_migration::migration::LegacyKeystore;

#[test]
fn migrate_from_android_2911() {
    let tests = [
            (
                include_str!("./fixtures/android-2911/04f85091-cf07-4761-8149-19c8e7dd39c5.json"),
                "11111111",
                Source::Mnemonic,
                "Cosmos",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/5e870760-0e65-4e2c-a56b-f57c340cfc49.json"),
                "12341234",
                Source::Private,
                "ksmaccount",
                "40b241ebd06c214ae6d0df24d889b25bf0506d12aa0d756eb7be050233542c50ffe8721c5955d24a25133d0f60906283a8fab3eb6d0b78c9d59b29ff7b9b159b",
            ),
            (
                include_str!("./fixtures/android-2911/7c3db9bb-b714-4698-a1a3-64473dce6841.json"),
                "11111111",
                Source::Mnemonic,
                "TRX",
                "crazy appear check gaze film saddle work jump guide surprise country chapter",
            ),
            (
                include_str!("./fixtures/android-2911/7c5b41ce-2bee-4797-b795-8150979e6248.json"),
                "11111111",
                Source::Private,
                "ETH",
                "ad6d1a046afa5a00922f58d6ed4bec4f4376bd44740529f25a253e635a93422e",
            ),
            (
                include_str!("./fixtures/android-2911/9c6c8a23-5026-4acd-b124-bc789766ae63.json"),
                "11111111",
                Source::KeystoreV3,
                "ETH",
                "0f03ff97b01103a8e90a3c652f811bbd3a5d30aa0ea5b6ee9e5c3ce24073d842",
            ),
            (
                include_str!("./fixtures/android-2911/54cc1a75-12e3-41b7-b1cc-71a67a2d185a.json"),
                "11111111",
                Source::Mnemonic,
                "q",
                "essence keep wheat ankle idea dream there destroy size budget attitude aerobic",
            ),
            (
                include_str!("./fixtures/android-2911/69b2d6a0-e57b-4152-bb02-0cc43fb561cb.json"),
                "11111111",
                Source::Mnemonic,
                "DOT",
                "wreck adult slender brass inject spring pill build run walk aerobic crash",
            ),
            (
                include_str!("./fixtures/android-2911/85eb7383-ab01-4491-bfef-708b7ab63fcd.json"),
                "11111111",
                Source::Wif,
                "BTC",
                "cf98ce36c05a8e3605d2f533bd812d0e24c7a792530b601cffb57488bad45b6b",
            ),
            (
                include_str!("./fixtures/android-2911/399f5c5a-f2cb-45d3-9440-1b3c5c0cc39a.json"),
                "11111111",
                Source::Mnemonic,
                "KSM",
                "purity mountain arena fit month enough tired mind short garage vital scorpion",
            ),
            (
                include_str!("./fixtures/android-2911/502bc8f1-4c4f-491e-8550-918c81389503.json"),
                "11111111",
                Source::Mnemonic,
                "BTC",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/577e0968-e044-43c3-9cb8-cb1e3a199529.json"),
                "11111111",
                Source::Mnemonic,
                "CKB",
                "nurse grace cloud kit mixed throw find crack witness shed rocket raven",
            ),
            (
                include_str!("./fixtures/android-2911/734e3c8a-f1a4-40a8-9be8-0ab3076d3190.json"),
                "11111111",
                Source::Mnemonic,
                "XTZ",
                "page place valid goat hockey always picnic step bitter speed naive surround",
            ),
            (
                include_str!("./fixtures/android-2911/42688af7-ad87-42d2-ba2e-38d0d2d88c54.json"),
                "11111111",
                Source::Wif,
                "BTC",
                "2c8f3ab066ab130db2c273044c48004ec2fb3eb9d1ed8663b45153a2ac6e2414",
            ),
            (
                include_str!("./fixtures/android-2911/55569fb0-1642-497f-93b3-d788fbade733.json"),
                "11111111",
                Source::Private,
                "",
                "4b7cba3be2086a48f09485a63edbe0ddd1bf110ae7ee84616410fcab89472e74",
            ),
            (
                include_str!("./fixtures/android-2911/576350d1-c863-45d4-aee5-5e111a00fc91.json"),
                "11111111",
                Source::Private,
                "",
                "cd58818886a3a557cb0fb62554af62e1b550bfcfe4a6d021df0d6c1098fe13ef",
            ),
            (
                include_str!("./fixtures/android-2911/aa1f67af-5237-43b8-af55-8e65b66deedc.json"),
                "11111111",
                Source::Mnemonic,
                "ATOM",
                "crazy appear check gaze film saddle work jump guide surprise country chapter",
            ),
            (
                include_str!("./fixtures/android-2911/b16bc74d-a80d-4d9f-b600-143a27c9c2df.json"),
                "11111111",
                Source::Mnemonic,
                "BCH",
                "scene hurry dawn symptom flag enough floor river runway estate swim betray",
            ),
            (
                include_str!("./fixtures/android-2911/b6092d42-155c-4e94-ba09-0ffc7a35523e.json"),
                "11111111",
                Source::Mnemonic,
                "FIL",
                "hover summer chat perfect obtain artwork castle mountain mobile retreat giraffe capital",
            ),
            (
                include_str!("./fixtures/android-2911/b42279e9-38a8-4d06-b4ac-dbd19e552cdc.json"),
                "11111111",
                Source::Private,
                "",
                "2eac50d289112fed03d0bbcfbe50fcf568560aab4c00a47409c51c6a31b194b3",
            ),
            (
                include_str!("./fixtures/android-2911/b6678054-a3f2-4ee6-8ec4-5c37fabbc1f0.json"),
                "11111111",
                Source::Private,
                "",
                "8bb90efb3c5ce904bebfb63281c994621ecc5184917ace9a9e28222e1285f34f",
            ),
            (
                include_str!("./fixtures/android-2911/bea65809-2e16-46af-a2ab-21f034c149a8.json"),
                "11111111",
                Source::Mnemonic,
                "ETH",
                "crazy appear check gaze film saddle work jump guide surprise country chapter",
            ),
            (
                include_str!("./fixtures/android-2911/c3484a0e-b397-4904-bfa6-bcec59bc8354.json"),
                "11111111",
                Source::Mnemonic,
                "",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/d337b532-1ad9-4843-a5a0-b46d472f6410.json"),
                "11111111",
                Source::Private,
                "",
                "b8bf582e4a072964c6e44769ba928a85be7ef35e466defccdb6e82bf3534487c",
            ),
            (
                include_str!("./fixtures/android-2911/de518612-2d90-401a-aa5f-2add45f5acd0.json"),
                "11111111",
                Source::Mnemonic,
                "LTC",
                "goat wave draw civil little ugly shoot blast medal galaxy lobster bless",
            ),
            (
                include_str!("./fixtures/android-2911/e8a54847-aa14-4fd2-8ddf-495371a47af2.json"),
                "11111111",
                Source::Mnemonic,
                "EOS",
                "",
            ),
            (
                include_str!("./fixtures/android-2911/e3824175-14cd-4a09-b475-94dda9b3ec0e.json"),
                "11111111",
                Source::Private,
                "",
                "cbf6e3be8c7ada5073e6be01578885f8686480207a95f6b04edfba38dbfc8a85",
            ),
            (
                include_str!("./fixtures/android-2911/f5235fee-103f-4bed-8b35-465482da91cc.json"),
                "11111111",
                Source::Mnemonic,
                "ETH",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
        ];

    for t in tests {
        let json: Value = serde_json::from_str(t.0).unwrap();
        let id = json["id"].clone();
        let version = json["version"].as_i64().unwrap_or(0);
        match version {
            11000 | 11001 => {
                let keystore_upgrade = KeystoreUpgrade::new(json);
                assert!(keystore_upgrade.need_upgrade());

                let key = Key::Password(t.1.to_owned());

                let mut keystore = keystore_upgrade.upgrade(&key).unwrap();
                keystore.unlock(&key);

                assert_eq!(keystore.meta().source, t.2);
                assert_eq!(keystore.meta().name, t.3);
                assert_eq!(keystore.export().unwrap(), t.4);
            }
            3 | 44 | 1 => {
                let legacy = LegacyKeystore::from_json_str(t.0).unwrap();

                let key = Key::Password(t.1.to_owned());

                let mut keystore = legacy.migrate(&key).unwrap();
                keystore.unlock(&key);

                assert_eq!(keystore.meta().source, t.2);
                assert_eq!(keystore.meta().name, t.3);
                assert_eq!(keystore.export().unwrap(), t.4);
            }
            _ => {}
        }
    }
}
