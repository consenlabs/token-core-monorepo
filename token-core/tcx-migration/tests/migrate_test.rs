#[cfg(test)]
mod tests {
    use serde_json::Value;
    use tcx_constants::TEST_PASSWORD;
    use tcx_crypto::Key;
    use tcx_keystore::keystore::IdentityNetwork;
    use tcx_keystore::Source;
    use tcx_migration::keystore_upgrade::KeystoreUpgrade;
    use tcx_migration::migration::LegacyKeystore;

    #[test]
    fn test_migrate_from_old_app() {
        let tests = [
            (
                include_str!("./fixtures/ios-214/00fc0804-7cea-46d8-9e95-ed1efac65358"),
                "2d7380db28736ae5b0693340a5731e137759d32bbcc1f7988574bc5a1ffd97f3411b4edc14ea648fa17d511129e81a84d2b8a00d45bc37f4784e49b641d5c3be",
                Source::Mnemonic,
                "BTC",
                "",
                "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            ),
            (
                include_str!("./fixtures/ios-214/0597526e-105f-425b-bb44-086fc9dc9568"),
                "ee95c730e4638cede7c74b2576c1c0f5011860ab384637a1c5d0eb81394b3505474984934b164b3767eb093b16edcfd86f9822606f58166188b8fe9013c10741",
                Source::Mnemonic,
                "ETH",
                "",
                "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            ),
            (
                include_str!("./fixtures/ios-214/0a2756cd-ff70-437b-9bdb-ad46b8bb0819.json"),
                "30d3639d4d1a52a8a3993712c1b1393129da06560dc7063e1d1132a155e6f701da4b7b7e3e10d648c49af3b34aed66771dec3b8387037a299e7bb6e7ae506633",
                Source::Mnemonic,
                "",
                "",
                "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            ),
            (
                include_str!("./fixtures/ios-214/300b42bc-0948-4734-82cb-4293dfeeefd2.json"),
                "34140a19bb7fe72866da4c57a03934b0ccf543c7a5caca06a1c323013dcecc034e0ae750f9742513b66bd8acccc37b72ec77a95ff1b5232c6f1473fc35a0508c",
                Source::Mnemonic,
                "Imported 6",
                "",
                "calm release clay imitate top extend close draw quiz refuse shuffle injury",
            ),
            (
                include_str!("./fixtures/ios-214/46e8e653-dd05-4217-b225-faafc8451a2c.json"),
                "2e70651f06a28d2f6053a90ee55ab8cb14518ab82182cd922926b4239713286ac6746ad4448608fc1599e6f4e0af33c65f70bc5de13a376933e5e145681d0f80",
                Source::Private,
                "",
                "secp256k1",
                "f9b3659f7246722270becdf9e67094b03e98a4a166a7299f0377bf735b501713",
            ),
            (
                include_str!("./fixtures/ios-214/483cb13e-5e59-4428-a219-018de4ce60f6.json"),
                "d175dad756f59a59b6a311f2b369802537d92011c8e3bf6dc2dfaf8df00d942648bf83133bd0204ebc43efcbd0ab79a8d5551c8dcf7ae1f67fc2d1d4aff33c06",
                Source::Private,
                "",
                "secp256k1",
                "8d3730ce79d9e0e829d480d88b29e8507755c282549dd80f6c0633804663a80a",
            ),
            (
                include_str!("./fixtures/ios-214/4b07b86f-cc3f-4bdd-b156-a69d5cbd4bca.json"),
                "1a60471067b6c6a3202e0014de2ce9b2d45fd73e2289b3cc3d8e5b58fe99ff242fd61e9fe63e75abbdc0ed87a50756cc10c57daf1d6297b99ec9a3b174eee017",
                Source::Private,
                "",
                "secp256k1",
                "685634d212eabe016a1cb09d9f1ea1ea757ebe590b9a097d7b1c9379ad280171",
            ),
            (
                include_str!("./fixtures/ios-214/4d5cbfcf-aee1-4908-9991-9d060eb68a0e.json"),
                "b009d3c4e961411836028a9fffbea994e03c71f75589a571cd52125884537f2ac165b92e7bc49c7828d4be0c5c05263a306744f0b9dc785142c8562d45ce4345",
                Source::Private,
                "",
                "ed25519",
                "c0b5db8581dab39e23ec34fed0662cfbafd8fdfcb90a041f4fdef9d2be098da3",
            ),
            (
                include_str!("./fixtures/ios-214/60573d8d-8e83-45c3-85a5-34fbb2aad5e1"),
                "8f2316895af6d58b5b75d424977cdaeae2a619c6b941ca5f77dcfed592cd3b23b698040caf397df6153db6f2d5b2815bf8f8cd32f99998ca46534242df82d1ca",
                Source::KeystoreV3,
                "Imported 2",
                "secp256k1",
                "7e480e9ef0faccdf1a3aa773682742e099620f6177e95a878c2a612a0785fc7c",
            ),
            (
                include_str!("./fixtures/ios-214/6c20aab6-1596-456d-9749-212e6139c5ed"),
                "8c4900e4e629a026af957d2432a4aacf6ea29a6da6e930a05b68e6b001990457351e03546805082cfd2aca196a0448817fb5d8ff73b4f27a093af256a52ca1f6",
                Source::Mnemonic,
                "Imported 7",
                "",
                "calm release clay imitate top extend close draw quiz refuse shuffle injury",
            ),
            (
                include_str!("./fixtures/ios-214/6c3eae60-ad03-48db-a5e5-61a6f72aef8d"),
                "9f65c31b4a61c430cd6c976e7f1b1b912bb09b46ec718447bbb5dccc353b19becb6b386405b3fcc7d43bd8e617764c3407d45824e52984d0074ac3f75c68bd92",
                Source::Mnemonic,
                "EOS",
                "",
                "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            ),
            (
                include_str!("./fixtures/ios-214/792a0051-16d7-44a7-921a-9b4a0c893b8f"),
                "ebe2739dd04525823b967b914a74a5dedd0086622d0da3449c1354199518673dd33fca8f6bd64870d6e6dc28b0f6e9de169243679b1668750f23cfe9523c03b3",
                Source::Mnemonic,
                "Imported 12",
                "",
                "calm release clay imitate top extend close draw quiz refuse shuffle injury",
            ),
            (
                include_str!("./fixtures/ios-214/949bada8-776c-4554-ad0c-001e3726a0f8.json"),
                TEST_PASSWORD,
                Source::SubstrateKeystore,
                "test account",
                "sr25519",
                "70e74176bfe0e2ae30f75653ab075deee9dae54437cb249e311ca7fef495f34b7351a3f69c82513bcd0c91ca16c99ca116cf87be91683baecab352a9be69f693",
            ),
            (
                include_str!("./fixtures/ios-214/9b696367-69c1-4cfe-8325-e5530399fc3f"),
                "89afe9331bdc5b8239f31d8dbed1699da290c44b2220eb4735c54171db664f2f09f1b0fdd5182e2bbd85ef10d5507a5f31d8a2f553666cb3024745f79cd83de5",
                Source::Mnemonic,
                "Imported 4",
                "",
                "calm release clay imitate top extend close draw quiz refuse shuffle injury",
            ),
            (
                include_str!("./fixtures/ios-214/9e3e1a17-ccad-4d93-98ab-cfe1e3f82ed3"),
                "8a98b183cc42331a6bb3a585e7808c376e21e625b0c82dc245e04c3333a123ad1cf022319a21af31ca371cbc3d713b738792f82b84db3978b3e1a6cdeee019fb",
                Source::Mnemonic,
                "Imported 3",
                "",
                "calm release clay imitate top extend close draw quiz refuse shuffle injury",
            ),
            (
                include_str!("./fixtures/ios-214/9f4acb4a-7431-4c7d-bd25-a19656a86ea0"),
                "a5b0cb9cb0536d6ec6ab21da77415bd59aff62c44c1da40d377c4faf2a44608693a72efb4079f57a5dca710ecff75dc5b54beb4ad6d9f9d47b63583810b50c61",
                Source::Wif,
                "Imported 13",
                "secp256k1",
                "8d3730ce79d9e0e829d480d88b29e8507755c282549dd80f6c0633804663a80a",
            ),
            (
                include_str!("./fixtures/ios-214/a7294912-b24f-44ba-86c1-48d76117808a.json"),
                "bee56a3cc9e6536dd22a695742ff1b4a00a797fa6c0ddd6f2c3bfd2ec25d05d61918ab3ceaf5c135f771d957889ee2b361c5d70f1911cc8857299d349a0d9ee6",
                Source::Private,
                "",
                "secp256k1",
                "a392604efc2fad9c0b3da43b5f698a2e3f270f170d859912be0d54742275c5f6",
            ),
            (
                include_str!("./fixtures/ios-214/ac59ccc1-285b-47a7-92f5-a6c432cee21a"),
                "4d9f1005a3e826d6f740c81676acf37d397f99354f3afdbe09b6ac02c93e3fb6a259063fa1ac3c89a79d84237d1d5ffe3b78ddb37abd6bd5b6811a9745bb7967",
                Source::Mnemonic,
                "COSMOS",
                "",
                "inject kidney empty canal shadow pact comfort wife crush horse wife sketch",
            ),
            (
                include_str!("./fixtures/ios-214/d9e3bb9c-87fd-4836-b146-10a3e249eb75"),
                "01073f22079380d2180300c518f6b510d4761fd83ce738271460c9e745b9055dabb28f93ff3a8fd54e0c71c005b5e799f8d52bcce1a81e08b5f15f9604531574",
                Source::Wif,
                "Imported 14",
                "secp256k1",
                "8d3730ce79d9e0e829d480d88b29e8507755c282549dd80f6c0633804663a80a",
            ),
            (
                include_str!("./fixtures/ios-214/f3615a56-cb03-4aa4-a893-89944e49920d"),
                "79c74b67fc73a255bc66afc1e7c25867a19e6d2afa5b8e3107a472de13201f1924fed05e811e7f5a4c3e72a8a6e047a80393c215412bde239ec7ded520896630",
                Source::Private,
                "Imported 1",
                "secp256k1",
                "4b8e7a47497d810cd11f209b8ce9d3b0eec34e85dc8bad5d12cb602425dd3d6b",
            ),
            (
                include_str!("./fixtures/ios-214/fbdc2a0b-58d5-4e43-b368-a0cb1a2d17cb.json"),
                "f3207a9f25adbdae5eff58bb13a9d9be4d763c6d47269fb14e4bd7a59ed667ba7282f1ba40746c60ae842c3f9dfeba91060f29f547ef2a94a66cfee93573ffaa",
                Source::Private,
                "",
                "bls12-381",
                "8bb90efb3c5ce904bebfb63281c994621ecc5184917ace9a9e28222e1285f34f",
            ),
            (
                include_str!("./fixtures/android-2911/04f85091-cf07-4761-8149-19c8e7dd39c5.json"),
                "cba27920687a7022e4ad05be168216446e0bed96ab281f682af5ecfb4b34a746f4575b6f3416db0aac14f0f1830fd0bc4e239a5033234b831e9928c1ae6115ce",
                Source::Mnemonic,
                "Cosmos",
                "",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/5e870760-0e65-4e2c-a56b-f57c340cfc49.json"),
                "12341234",
                Source::SubstrateKeystore,
                "ksmaccount",
                "sr25519",
                "40b241ebd06c214ae6d0df24d889b25bf0506d12aa0d756eb7be050233542c50ffe8721c5955d24a25133d0f60906283a8fab3eb6d0b78c9d59b29ff7b9b159b",
            ),
            (
                include_str!("./fixtures/android-2911/7c3db9bb-b714-4698-a1a3-64473dce6841.json"),
                "33dd510b32e8e591be3efc4a05fb5bcaefe4a66dc1cb95372e73ecd2d814fa232fab00ac6bcae1a51bec610e016e243ad98eb37c5dd543b72a14bf2ffdf6f448",
                Source::Mnemonic,
                "TRX",
                "",
                "crazy appear check gaze film saddle work jump guide surprise country chapter",
            ),
            (
                include_str!("./fixtures/android-2911/7c5b41ce-2bee-4797-b795-8150979e6248.json"),
                "cfc28c6a94f3fc60a0d88f6be695dc14a33b83befdfbfac909caa72f77bea7f3973f4cca4e444bcaf5bc374343e7432cd1ba9230bb4473c88e753ed5b8997613",
                Source::Private,
                "ETH",
                "secp256k1",
                "ad6d1a046afa5a00922f58d6ed4bec4f4376bd44740529f25a253e635a93422e",
            ),
            (
                include_str!("./fixtures/android-2911/9c6c8a23-5026-4acd-b124-bc789766ae63.json"),
                "b71b6ce1ea9e7484055e713443fb27fa38fc9a890a86ef5c59a8706ecc7272f6e17bd142e4e5088d5bb93cb8fb27e4edcb9e71a703e134d38f790f799b9e2ba2",
                Source::KeystoreV3,
                "ETH",
                "secp256k1",
                "0f03ff97b01103a8e90a3c652f811bbd3a5d30aa0ea5b6ee9e5c3ce24073d842",
            ),
            (
                include_str!("./fixtures/android-2911/54cc1a75-12e3-41b7-b1cc-71a67a2d185a.json"),
                "ce07837fa3f5c96d6387dcbeb8d1ea88a8685285fada4c1b8e2b0eb2f2cee37d5cbe74ca3967beee1a683e540e56cd3ff22318fce47e562f59768a41aa6ce258",
                Source::Mnemonic,
                "q",
                "",
                "essence keep wheat ankle idea dream there destroy size budget attitude aerobic",
            ),
            (
                include_str!("./fixtures/android-2911/69b2d6a0-e57b-4152-bb02-0cc43fb561cb.json"),
                "1caface946086714e1127b7796f53e01b8e159c738cae0a622bc28ee425fece70736e23ef6b4f3dd2d98c2070ff892ebc7674ec3b3a7073160da66d0e673b75b",
                Source::Mnemonic,
                "DOT",
                "",
                "wreck adult slender brass inject spring pill build run walk aerobic crash",
            ),
            (
                include_str!("./fixtures/android-2911/85eb7383-ab01-4491-bfef-708b7ab63fcd.json"),
                "6767a718812ed251a52423c46822a85a6f1ab89d804951729cd38dc3719915ae95278a5e73e24eab20b4a7f56ef72023796ec2c3eeb3c67971569de9068420b6",
                Source::Wif,
                "BTC",
                "secp256k1",
                "cf98ce36c05a8e3605d2f533bd812d0e24c7a792530b601cffb57488bad45b6b",
            ),
            (
                include_str!("./fixtures/android-2911/399f5c5a-f2cb-45d3-9440-1b3c5c0cc39a.json"),
                "c3c15cb6ab57f2b940d1ff6d01eea543d8acf3f78a59f475b2fe2c47beb3343d1f3e970a794886e6951250e093b0be22fa907d373405247344eb7e14d24357a9",
                Source::Mnemonic,
                "KSM",
                "",
                "purity mountain arena fit month enough tired mind short garage vital scorpion",
            ),
            (
                include_str!("./fixtures/android-2911/502bc8f1-4c4f-491e-8550-918c81389503.json"),
                "36a7d0c200e779103ab0272c799062696796a57c287f26d6840037c78eba7db1866405f88955f44ef4b672f5e2fff6c5c1f84434037f303fb579253b5c795cf6",
                Source::Mnemonic,
                "BTC",
                "",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/577e0968-e044-43c3-9cb8-cb1e3a199529.json"),
                "585122eea4a7317fad3a2af4aa8b70f40e4b068711ed96f3ec0b01077e909afe60db149c56dc9ff5c7b4f9afdcd25799f976eaf271933b25d2e5a8f3a76821e7",
                Source::Mnemonic,
                "CKB",
                "",
                "nurse grace cloud kit mixed throw find crack witness shed rocket raven",
            ),
            (
                include_str!("./fixtures/android-2911/734e3c8a-f1a4-40a8-9be8-0ab3076d3190.json"),
                "e653fd9f7e4abe652f64bd47eaa9a601091c007616b4746ac6def85f7dc2600f3ee162b483af9a622ae84c41009f29d10b8e89c379d96bed01a9d62c2c60b0da",
                Source::Mnemonic,
                "XTZ",
                "",
                "page place valid goat hockey always picnic step bitter speed naive surround",
            ),
            (
                include_str!("./fixtures/android-2911/42688af7-ad87-42d2-ba2e-38d0d2d88c54.json"),
                "e87e36c4ed257671c8b45fc746c99f1b68906520aedddcfb4984d4d9c9131d22d7405cfe3feb3f452bfc48cd20f37a828e5f09c0696a49f027a9b1be54b57054",
                Source::Wif,
                "BTC",
                "secp256k1",
                "2c8f3ab066ab130db2c273044c48004ec2fb3eb9d1ed8663b45153a2ac6e2414",
            ),
            (
                include_str!("./fixtures/android-2911/55569fb0-1642-497f-93b3-d788fbade733.json"),
                "974e0c18123378f0c30cbe92857498b39c8a1c615488d5dd934fe4d7228e89daf0fc5915df1bb320e3a70443da675d6571871b9abff3f183df845b5d9f72d0a8",
                Source::Private,
                "",
                "secp256k1",
                "4b7cba3be2086a48f09485a63edbe0ddd1bf110ae7ee84616410fcab89472e74",
            ),
            (
                include_str!("./fixtures/android-2911/576350d1-c863-45d4-aee5-5e111a00fc91.json"),
                "8c4b85faa4b9859ecdbf93e8b876f67822697be108a437768ae9751a0b154c6e5c0f58fbe2140eefbe102bb0df6ecea5b04ddb95f268035f7c87ddbd016dbef5",
                Source::Private,
                "",
                "secp256k1",
                "cd58818886a3a557cb0fb62554af62e1b550bfcfe4a6d021df0d6c1098fe13ef",
            ),
            (
                include_str!("./fixtures/android-2911/aa1f67af-5237-43b8-af55-8e65b66deedc.json"),
                "f26184d66b880614fcb059c753ec8242909b60888b48d1e4302ee867a4a8c8e1431b10824bfec028dcd09757ff1881a153229078bfd56b35f9b72e2cdff42030",
                Source::Mnemonic,
                "ATOM",
                "",
                "crazy appear check gaze film saddle work jump guide surprise country chapter",
            ),
            (
                include_str!("./fixtures/android-2911/b16bc74d-a80d-4d9f-b600-143a27c9c2df.json"),
                "887b54d5c570da674ff66d261288d4c6d6b66107603b9e8dfad4c53c6fd8faaf8992e433bee365cfe62d95e8fda86df6c51449783172de6df7af2b506d7b87bc",
                Source::Mnemonic,
                "BCH",
                "",
                "scene hurry dawn symptom flag enough floor river runway estate swim betray",
            ),
            (
                include_str!("./fixtures/android-2911/b6092d42-155c-4e94-ba09-0ffc7a35523e.json"),
                "dae7e9317763462795e8a21ecd61d9c7ce05c046f7299afd6a4928ab5099236c86f4cd080e83c093d6b356378c0fbbcbdd5ec726bcd7ac55c3683888c316548f",
                Source::Mnemonic,
                "FIL",
                "",
                "hover summer chat perfect obtain artwork castle mountain mobile retreat giraffe capital",
            ),
            (
                include_str!("./fixtures/android-2911/b42279e9-38a8-4d06-b4ac-dbd19e552cdc.json"),
                "a17c5c65bc255987ce9b7c53b1c67bcc509810b87de786acc037886070a7f94688e241c8076fc3359c3cd977c2f2e4555715396829a2a8f30e8788732b899ba9",
                Source::Private,
                "",
                "secp256k1",
                "2eac50d289112fed03d0bbcfbe50fcf568560aab4c00a47409c51c6a31b194b3",
            ),
            (
                include_str!("./fixtures/android-2911/b6678054-a3f2-4ee6-8ec4-5c37fabbc1f0.json"),
                "384560d9c87168b22afe219e9515fc059321a9ac4224197d200f5ac96f7217ed81d4f817da30cb40bc2a898531c32ad9fe82c66f73b9c98c0228ea380acace6c",
                Source::Private,
                "",
                "bls12-381",
                "8bb90efb3c5ce904bebfb63281c994621ecc5184917ace9a9e28222e1285f34f",
            ),
            (
                include_str!("./fixtures/android-2911/bea65809-2e16-46af-a2ab-21f034c149a8.json"),
                "f0362abc4ce055640bc441ab28534734ef1971aa07a8460f03bdb4e052d8428ed69afe7a9937a04e977050ce49b9e4098a4d1116c45f310e8aa2381336ff50ae",
                Source::Mnemonic,
                "ETH",
                "",
                "crazy appear check gaze film saddle work jump guide surprise country chapter",
            ),
            (
                include_str!("./fixtures/android-2911/c3484a0e-b397-4904-bfa6-bcec59bc8354.json"),
                "8796c39545a9d4a59f1fd0ca9a3c7dabf872ced324a78860e0f3354902e0337998e9d5ffe2a9c7b75603338d495917caa40f4691242c958db2cd1d8e8aa8c774",
                Source::Mnemonic,
                "",
                "",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/d337b532-1ad9-4843-a5a0-b46d472f6410.json"),
                "3290219cac64298897e226d5bf91164478593b2ccfe9c0139c8ecbb2cdd9769c0696d30e74e94aba45bf4f14b7aa6c9a7436b23630c8ee1eb899d0111ec53bbc",
                Source::Private,
                "",
                "ed25519",
                "b8bf582e4a072964c6e44769ba928a85be7ef35e466defccdb6e82bf3534487c",
            ),
            (
                include_str!("./fixtures/android-2911/de518612-2d90-401a-aa5f-2add45f5acd0.json"),
                "1654dc67ac799b2bd5815fe797d3fc1b7290c5977ca5650755e4df76e830bc8e5218fea898c175d95e0a09d8ea8a6f75702442734daf82833d95de0fe7e232bc",
                Source::Mnemonic,
                "LTC",
                "",
                "goat wave draw civil little ugly shoot blast medal galaxy lobster bless",
            ),
            (
                include_str!("./fixtures/android-2911/e8a54847-aa14-4fd2-8ddf-495371a47af2.json"),
                "ad5ab19f4e5b4a7559943236a11d0efbdb80962cb46bd6edf3dab7a0f1a541231d09fbc28559f7f03cc341841b3451813bcd882a4dd6cc96e776b3c2379ff9dd",
                Source::Mnemonic,
                "EOS",
                "",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
            (
                include_str!("./fixtures/android-2911/e3824175-14cd-4a09-b475-94dda9b3ec0e.json"),
                "0852c029bd7267a7ee2a08e2bcfcf04197461b027b636cbc928730b60dff397006c7379925760221527ed06503ab080505bf21d11129baeab3d955957bcf79da",
                Source::Private,
                "",
                "secp256k1",
                "cbf6e3be8c7ada5073e6be01578885f8686480207a95f6b04edfba38dbfc8a85",
            ),
            (
                include_str!("./fixtures/android-2911/f5235fee-103f-4bed-8b35-465482da91cc.json"),
                "d34efacde823c5581869e359351d1b8b7c06f2787ea50097d5f6db1fc791c9d065a4e7c0062589685ba21d57819f3fccf7294677c623e902f553e6bbf4b7876f",
                Source::Mnemonic,
                "ETH",
                "",
                "segment need pole intact network hope level donkey machine razor advice silent",
            ),
        ];

        for t in tests {
            let json: Value = serde_json::from_str(t.0).unwrap();
            let version = json["version"].as_i64().unwrap_or(0);
            match version {
                11000 | 11001 => {
                    let keystore_upgrade = KeystoreUpgrade::new(json.clone());
                    assert!(keystore_upgrade.need_upgrade());

                    let key = if version == 11001
                        && (t.0.contains("POLKADOT") || t.0.contains("KUSAMA"))
                    {
                        Key::Password(t.1.to_string())
                    } else {
                        Key::DerivedKey(t.1.to_owned())
                    };

                    let mut keystore = keystore_upgrade
                        .upgrade(&key, &IdentityNetwork::Testnet)
                        .unwrap();
                    let _ = keystore.unlock(&key);

                    assert_eq!(keystore.meta().source, t.2);
                    assert_eq!(keystore.meta().name, t.3);
                    if keystore.meta().source != Source::NewMnemonic
                        && keystore.meta().source != Source::Mnemonic
                    {
                        assert_eq!(keystore.get_curve().unwrap().as_str(), t.4);
                    }
                    assert_eq!(keystore.export().unwrap(), t.5);
                }
                3 | 44 | 1 | 10001 => {
                    let legacy = LegacyKeystore::from_json_str(t.0).unwrap();

                    let key = Key::DerivedKey(t.1.to_owned());

                    let mut keystore = legacy.migrate(&key, &IdentityNetwork::Testnet).unwrap();
                    let _ = keystore.unlock(&key);

                    assert_eq!(keystore.meta().source, t.2);
                    assert_eq!(keystore.meta().name, t.3);
                    if keystore.meta().source != Source::NewMnemonic
                        && keystore.meta().source != Source::Mnemonic
                    {
                        assert_eq!(keystore.get_curve().unwrap().as_str(), t.4);
                    }
                    assert_eq!(keystore.export().unwrap(), t.5);
                }
                _ => {}
            }
        }
    }
}
