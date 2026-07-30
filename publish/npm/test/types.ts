import {
  createImKeyCore,
  type FilecoinSignTxParams,
  type NervosSignTxParams,
} from "../index.js";

const imkey = createImKeyCore();

declare const filecoin: FilecoinSignTxParams;
declare const nervos: NervosSignTxParams;

void imkey.signTx(filecoin).then((result) => result.cid);
void imkey.signTx(nervos).then((result) => result.witnesses);
void imkey.getFirmwareVersion();
void imkey.configureTsm("https://example.com/imkey").then((baseUrl) => baseUrl.toUpperCase());
void imkey.cosCheckUpdate().then((response) => response._ReturnData.latestBleVersion);
void imkey.cosUpdate();
