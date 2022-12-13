package com.mk.imkeydemo.core.wallet.transaction;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import com.google.protobuf.Any;
import com.mk.imkeydemo.utils.ResourcesManager;
import com.mk.imkeylibrary.common.Messages;
import com.mk.imkeylibrary.common.Path;
import com.mk.imkeylibrary.common.TransactionSignedResult;
import com.mk.imkeylibrary.exception.ImkeyException;
import com.mk.imkeylibrary.keycore.EthApi;
import com.mk.imkeylibrary.keycore.RustApi;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;

import ethapi.Eth;

public class ImKeyETHTransactionTest {

    //contains failCount、successCount、failed test case name
    public static Map<String, Object> result = new HashMap<String, Object>();

    public static Map<String, Object> testEthTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "ethtransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONObject tran = testcase.getJSONObject("transaction");

                BigInteger nonce = BigInteger.valueOf(tran.getLong("nonce"));
                BigInteger gasPrice = BigInteger.valueOf(tran.getLong("gasPrice"));
                BigInteger gasLimit = BigInteger.valueOf(tran.getLong("gasLimit"));
                String to = tran.getString("to");
                BigInteger value = BigInteger.valueOf(tran.getLong("value"));
                String data = tran.getString("data");
                String v = tran.getString("v");

                JSONObject pre = testcase.getJSONObject("preview");

                ethapi.Eth.EthTxReq ethTxReq = ethapi.Eth.EthTxReq.newBuilder()
                        .setPath(Path.ETH_LEDGER)
                        .setChainId(v)
                        .setNonce(nonce.toString())
                        .setGasPrice(gasPrice.toString())
                        .setGasLimit(gasLimit.toString())
                        .setTo(to)
                        .setValue(value.toString())
                        .setData(data)
                        .setPayment(pre.getString("payment"))
                        .setReceiver(pre.getString("receiver"))
                        .setSender(pre.getString("sender"))
                        .setFee(pre.getString("fee"))
                        .build();

                Any any = Any.newBuilder()
                        .setValue(ethTxReq.toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("eth_tx_sign")
                        .setParam(any)
                        .build();

                Boolean retry = true;
                int tryCount = 0;
                while (retry) {
                    tryCount++;
                    try {

                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                        // clear_err
                        RustApi.INSTANCE.clear_err();

                        String hex = NumericUtil.bytesToHex(action.toByteArray());

                        String result = RustApi.INSTANCE.call_imkey_api(hex);

                        //
                        String error = RustApi.INSTANCE.get_last_err_message();
                        if (!"".equals(error) && null != error) {
                            api.Api.Response errorResponse = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
                            Boolean isSuccess = errorResponse.getIsSuccess();
                            if (!isSuccess) {
                                LogUtil.d("异常： " + errorResponse.getError());
                                failedCaseName.add(key);
                                failCount++;
                                retry = false;
                                continue;
                            }
                        }

                        ethapi.Eth.EthTxRes response = ethapi.Eth.EthTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                        String txHash = response.getTxHash();
                        String signature = response.getTxData();
                        LogUtil.d("signature：" + signature);
                        LogUtil.d("txHash：" + txHash);
                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                        if (txHash.equals(testcase.getString("txHash"))) {
                            LogUtil.e("×××××××××××××××××××××××××××××××××××成功×××××××××××××××××××××××××××××××××××××××××××××××");
                            successCount++;
                        } else {
                            failedCaseName.add(key);
                            failCount++;
                        }
                        retry = false;
                    } catch (ImkeyException e) {
                        if (!Messages.IMKEY_BLUETOOTH_CHANNEL_ERROR.equals(e.getMessage()) || tryCount >= 3) {
                            retry = false;
                            failedCaseName.add(key + ": " + e.getMessage());
                            failCount++;
                        }
                    }
                }
            }

        } catch (Exception e) {
            throw new ImkeyException(e);
        }

        result.put("failCount", failCount);
        result.put("successCount", successCount);
        result.put("failedCaseName", failedCaseName);

        return result;

    }


    /*public static Map<String, Object> testEthTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "ethtransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {
                ArrayList<ImKeyBitcoinTransaction.UTXO> utxo = new ArrayList<>();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);

                JSONObject tran = testcase.getJSONObject("transaction");

                BigInteger nonce = BigInteger.valueOf(tran.getLong("nonce"));
                BigInteger gasPrice = BigInteger.valueOf(tran.getLong("gasPrice"));
                BigInteger gasLimit = BigInteger.valueOf(tran.getLong("gasLimit"));
                String to = tran.getString("to");
                BigInteger value = BigInteger.valueOf(tran.getLong("value"));
                String data = tran.getString("data");
                String v = tran.getString("v");

                JSONObject pre = testcase.getJSONObject("preview");
                HashMap<String, String> preview = new HashMap<>();
                preview.put("payment", pre.getString("payment"));
                preview.put("receiver", pre.getString("receiver"));
                preview.put("sender", pre.getString("sender"));
                preview.put("fee", pre.getString("fee"));

                ImKeyEthereumTransaction ethTx = new ImKeyEthereumTransaction(nonce, gasPrice,gasLimit,to,value,data, preview);

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {
                        TransactionSignedResult result = ethTx.signTransaction(v, Path.ETH_LEDGER);
                        String txHash = result.getTxHash();
                        if(txHash.equals(testcase.getString("txHash"))) {
                            successCount ++;
                        } else {
                            failedCaseName.add(key);
                            failCount++;
                        }
                        retry = false;
                    } catch (ImkeyException e) {
                        if(!Messages.IMKEY_BLUETOOTH_CHANNEL_ERROR.equals(e.getMessage()) || tryCount >= 3) {
                            retry = false;
                            failedCaseName.add(key + ": " + e.getMessage());
                            failCount++;
                        }
                    }
                }
            }
        } catch (Exception e) {
            throw new ImkeyException(e);
        }

        result.put("failCount", failCount);
        result.put("successCount", successCount);
        result.put("failedCaseName", failedCaseName);

        return result;

    }*/


    public static Eth.EthTxRes testEthTxSign() {

        ethapi.Eth.EthTxReq ethTxReq = ethapi.Eth.EthTxReq.newBuilder()
                .setPath(Path.ETH_LEDGER)
                .setChainId("28")
                .setNonce("8")
                .setGasPrice("20000000008")
                .setGasLimit("189000")
                .setTo("0x3535353535353535353535353535353535353535")
                .setValue("512")
                .setData("")
                .setPayment("0.01 ETH")
                .setReceiver("0xE6F4142dfFA574D1d9f18770BF73814df07931F3")
                .setSender("0x6031564e7b2F5cc33737807b2E58DaFF870B590b")
                .setFee("0.0032 ether")
                .build();
        Eth.EthTxRes res = null;
        try {
            res = EthApi.signTx(ethTxReq);
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }

        return res;
    }

    /*public static TransactionSignedResult testEthTxSign() {
        HashMap<String, String> preview = new HashMap<>();
        preview.put("payment", "0.01 ETH");
        preview.put("receiver", "0xE6F4142dfFA574D1d9f18770BF73814df07931F3");
        preview.put("sender", "0x6031564e7b2F5cc33737807b2E58DaFF870B590b");
        preview.put("fee", "0.0032 ether");

        ImKeyEthereumTransaction ethereumTransaction = new ImKeyEthereumTransaction(BigInteger.valueOf(8L), BigInteger.valueOf(20000000008L),
                BigInteger.valueOf(189000L), "0x3535353535353535353535353535353535353535",
                BigInteger.valueOf(512), "", preview);

        TransactionSignedResult result = ethereumTransaction.signTransaction("28", Path.ETH_LEDGER);
        return result;
    }*/

    public static String testEthMsgSign() {
        String signature = null;

        try {

            String data = "Hello imKey";
            String sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b";

            ethapi.Eth.EthMessageSignReq ethMessageSignReq = ethapi.Eth.EthMessageSignReq.newBuilder()
                    .setPath(Path.ETH_LEDGER)
                    .setMessage(data)
                    .setSender(sender)
                    .build();

            Eth.EthMessageSignRes res = EthApi.signMessage(ethMessageSignReq);
            signature = res.getSignature();
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }
        return signature;
    }

    /*public static String testEthMsgSign() {
        String data = "Hello imKey";
        String sender = "0x6031564e7b2F5cc33737807b2E58DaFF870B590b";
        return new Eth().signPersonalMessage(Path.ETH_LEDGER, data, sender);
    }*/

}
