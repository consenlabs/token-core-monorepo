package com.mk.imkeydemo.core.wallet.transaction;

import android.content.Context;

import com.google.protobuf.Any;
import com.mk.imkeydemo.keycore.Constants;
import com.mk.imkeydemo.keycore.Path;
import com.mk.imkeydemo.keycore.RustApi;
import com.mk.imkeydemo.keycore.TransactionSignedResult;
import com.mk.imkeydemo.utils.NumericUtil;
import com.mk.imkeydemo.utils.ResourcesManager;


import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import im.imkey.imkeylibrary.common.Messages;
import im.imkey.imkeylibrary.exception.ImkeyException;
import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;

public class ImKeyOmniTransactionTest {

    //contains failCount、successCount、failed test case name
    public static Map<String, Object> result = new HashMap<String, Object>();

    public static Map<String, Object> testUxdtTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "usdttransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {

                btcapi.Btc.BtcTxReq.Builder builder = btcapi.Btc.BtcTxReq.newBuilder();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONArray utxoArray = testcase.getJSONArray("utxo");
                for (int i = 0; i < utxoArray.length(); i++) {

                    JSONObject utxoObj = utxoArray.getJSONObject(i);

                    btcapi.Btc.Utxo utxo = btcapi.Btc.Utxo.newBuilder()
                            .setTxHash(utxoObj.getString("txHash"))
                            .setVout(utxoObj.getInt("vout"))
                            .setAmount(utxoObj.getLong("amount"))
                            .setAddress(utxoObj.getString("address"))
                            .setScriptPubKey(utxoObj.getString("scriptPubKey"))
                            .setDerivedPath(utxoObj.getString("derivedPath"))
                            .build();
                    builder.addUnspents(utxo);

                }


                builder
                        .setTo(testcase.getString("to"))
                        .setAmount(testcase.getLong("amount"))
                        .setFee(testcase.getLong("fee"))
                        .setNetwork(Constants.MAINNET)
                        .setPathPrefix(Path.BTC_PATH_PREFIX)
                        .setPropertyId(testcase.getInt("propertyId"))
                        .build();


                Any any = Any.newBuilder()
                        .setValue(builder.build().toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("btc_usdt_tx_sign")
                        .setParam(any)
                        .build();

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {

                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                        // clear_err
                        RustApi.INSTANCE.clear_err();

                        String hex = NumericUtil.bytesToHex(action.toByteArray());

                        String result = RustApi.INSTANCE.call_imkey_api(hex);

                        //
                        String error = RustApi.INSTANCE.get_last_err_message();
                        if(!"".equals(error) && null != error) {
                            api.Api.Response errorResponse = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
                            Boolean isSuccess = errorResponse.getIsSuccess();
                            if(!isSuccess) {
                                LogUtil.d("异常： " + errorResponse.getError());
                                failedCaseName.add(key);
                                failCount++;
                                retry = false;
                                continue;
                            }
                        }

                        btcapi.Btc.BtcTxRes response = btcapi.Btc.BtcTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                        String signature = response.getTxData();
                        String tx_hash = response.getTxHash();

                        LogUtil.d("signature：" + signature);
                        LogUtil.d("tx_hash：" + tx_hash);
                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                        TransactionSignedResult signedResult = new TransactionSignedResult(signature, tx_hash);
                        String txHash = signedResult.getTxHash();
                        if(txHash.equals(testcase.getString("txHash"))) {
                            LogUtil.e("×××××××××××××××××××××××××××××××××××成功×××××××××××××××××××××××××××××××××××××××××××××××");
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

    }

    /*public static Map<String, Object> testUxdtTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "usdttransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {
                ArrayList<ImKeyOmniTransaction.UTXO> utxo = new ArrayList<>();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONArray utxoArray = testcase.getJSONArray("utxo");
                for (int i = 0; i < utxoArray.length(); i++) {

                    JSONObject utxoObj = utxoArray.getJSONObject(i);

                    utxo.add(new ImKeyOmniTransaction.UTXO(
                            utxoObj.getString("txHash"),
                            utxoObj.getInt("vout"),
                            utxoObj.getLong("amount"),
                            utxoObj.getString("address"),
                            utxoObj.getString("scriptPubKey"),
                            utxoObj.getString("derivedPath")
                    ));

                }

                ImKeyOmniTransaction transaction = new ImKeyOmniTransaction(
                        testcase.getString("to"),
                        testcase.getLong("amount"),
                        testcase.getLong("fee"),
                        testcase.getInt("propertyId"),
                        utxo,
                        testcase.getString("payment"),
                        testcase.getString("toDis"),
                        testcase.getString("from"),
                        testcase.getString("feeDis")
                );

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {
                        TransactionSignedResult result = transaction.signTransaction(Constants.MAINNET, Path.BTC_PATH_PREFIX);
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

    }
    */
    public static Map<String, Object> testUsdtSegwitTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "usdtsegwittransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {

                btcapi.Btc.BtcTxReq.Builder builder = btcapi.Btc.BtcTxReq.newBuilder();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONArray utxoArray = testcase.getJSONArray("utxo");

                for (int i = 0; i < utxoArray.length(); i++) {

                    JSONObject utxoObj = utxoArray.getJSONObject(i);

                    btcapi.Btc.Utxo utxo = btcapi.Btc.Utxo.newBuilder()
                            .setTxHash(utxoObj.getString("txHash"))
                            .setVout(utxoObj.getInt("vout"))
                            .setAmount(utxoObj.getLong("amount"))
                            .setAddress(utxoObj.getString("address"))
                            .setScriptPubKey(utxoObj.getString("scriptPubKey"))
                            .setDerivedPath(utxoObj.getString("derivedPath"))
                            .build();
                    builder.addUnspents(utxo);

                }


                builder
                        .setTo(testcase.getString("to"))
                        .setAmount(testcase.getLong("amount"))
                        .setFee(testcase.getLong("fee"))
                        //.setExtraData(extraData)
                        .setNetwork(Constants.MAINNET)
                        .setPathPrefix(Path.BTC_SEGWIT_PATH_PREFIX)
                        .setPropertyId(testcase.getInt("propertyId"))
                        .build();


                Any any = Any.newBuilder()
                        .setValue(builder.build().toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("btc_usdt_segwit_tx_sign")
                        .setParam(any)
                        .build();

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {

                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                        // clear_err
                        RustApi.INSTANCE.clear_err();

                        String hex = NumericUtil.bytesToHex(action.toByteArray());

                        String result = RustApi.INSTANCE.call_imkey_api(hex);

                        //
                        String error = RustApi.INSTANCE.get_last_err_message();
                        if(!"".equals(error) && null != error) {
                            api.Api.Response errorResponse = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
                            Boolean isSuccess = errorResponse.getIsSuccess();
                            if(!isSuccess) {
                                LogUtil.d("异常： " + errorResponse.getError());
                                failedCaseName.add(key);
                                failCount++;
                                retry = false;
                                continue;
                            }
                        }

                        btcapi.Btc.BtcSegwitTxRes response = btcapi.Btc.BtcSegwitTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                        String signature = response.getWitnessTxData();
                        String tx_hash = response.getTxHash();
                        String wtx_id = response.getWtxHash();
                        LogUtil.d("signature：" + signature);
                        LogUtil.d("tx_hash：" + tx_hash);
                        LogUtil.d("wtx_id：" + wtx_id);
                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                        if(tx_hash.equals(testcase.getString("txHash")) && wtx_id.equals(testcase.getString("wtxID"))) {
                            LogUtil.e("×××××××××××××××××××××××××××××××××××成功×××××××××××××××××××××××××××××××××××××××××××××××");
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

    }

    /*public static Map<String, Object> testUsdtSegwitTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "usdtsegwittransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {
                ArrayList<ImKeyBitcoinTransaction.UTXO> utxo = new ArrayList<>();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONArray utxoArray = testcase.getJSONArray("utxo");
                for (int i = 0; i < utxoArray.length(); i++) {

                    JSONObject utxoObj = utxoArray.getJSONObject(i);

                    utxo.add(new ImKeyBitcoinTransaction.UTXO(
                            utxoObj.getString("txHash"),
                            utxoObj.getInt("vout"),
                            utxoObj.getLong("amount"),
                            utxoObj.getString("address"),
                            utxoObj.getString("scriptPubKey"),
                            utxoObj.getString("derivedPath")
                    ));

                }

                ImKeyOmniTransaction transaction = new ImKeyOmniTransaction(
                        testcase.getString("to"),
                        testcase.getLong("amount"),
                        testcase.getLong("fee"),
                        testcase.getInt("propertyId"),
                        utxo,
                        testcase.getString("payment"),
                        testcase.getString("toDis"),
                        testcase.getString("from"),
                        testcase.getString("feeDis")
                );

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {
                        TransactionSignedResult result = transaction.signSegWitTransaction(Constants.MAINNET, Path.BTC_SEGWIT_PATH_PREFIX);
                        String txHash = result.getTxHash();
                        String wtxID = result.getWtxID();
                        if(txHash.equals(testcase.getString("txHash")) && wtxID.equals(testcase.getString("wtxID"))) {
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

    public static TransactionSignedResult testUxdtTxSign() {


        TransactionSignedResult signedResult = null;

        try {

            btcapi.Btc.Utxo utxo0 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("0dd195c815c5086c5995f43a0c67d28344ae5fa130739a5e03ef40fea54f2031")
                    .setVout(0)
                    .setAmount(14824854)
                    .setAddress("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
                    .setScriptPubKey("76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac")
                    .setDerivedPath("0/0")
                    .setSequence(4294967295l)
                    .build();


            btcapi.Btc.BtcTxReq btcTxReq = btcapi.Btc.BtcTxReq.newBuilder()
                    .setTo("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3")
                    .setAmount(10050000000L)
                    .setFee(4000)
                    .addUnspents(utxo0)
                    .setNetwork("TESTNET")
                    .setPathPrefix(Path.BITCOIN_TESTNET_PATH)
                    .setPropertyId(31)
                    .build();

            Any any = Any.newBuilder()
                    .setValue(btcTxReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("btc_usdt_tx_sign")
                    .setParam(any)
                    .build();

            String hex = NumericUtil.bytesToHex(action.toByteArray());

            // clear_err
            RustApi.INSTANCE.clear_err();

            String result = RustApi.INSTANCE.call_imkey_api(hex);

            String error = RustApi.INSTANCE.get_last_err_message();
            if(!"".equals(error) && null != error) {
                api.Api.Response errorResponse = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
                Boolean isSuccess = errorResponse.getIsSuccess();
                if(!isSuccess) {
                    LogUtil.d("异常： " + errorResponse.getError());

                }
            } else {
                btcapi.Btc.BtcTxRes response = btcapi.Btc.BtcTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                String signature = response.getTxData();
                String tx_hash = response.getTxHash();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("signature：" + signature);
                LogUtil.d("tx_hash：" + tx_hash);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                signedResult = new TransactionSignedResult(signature, tx_hash);
            }

        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }

        return signedResult;



/*
        utxo.add(new ImKeyOmniTransaction.UTXO(
                "0dd195c815c5086c5995f43a0c67d28344ae5fa130739a5e03ef40fea54f2031", 0,
                14824854, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));

        ImKeyOmniTransaction transaction = new ImKeyOmniTransaction("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3", 10050000000L,
                4000, 31, utxo, "100 USDT", "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3",
                "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", "0.0004 BTC");

        TransactionSignedResult result = transaction.signTransaction(Constants.TESTNET, Path.BITCOIN_TESTNET_PATH);
        return result;*/
    }

    /*
    public static TransactionSignedResult testUxdtTxSign() {
        ArrayList<ImKeyOmniTransaction.UTXO> utxo = new ArrayList<>();

        utxo.add(new ImKeyOmniTransaction.UTXO(
                "0dd195c815c5086c5995f43a0c67d28344ae5fa130739a5e03ef40fea54f2031", 0,
                14824854, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));

        ImKeyOmniTransaction transaction = new ImKeyOmniTransaction("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3", 10050000000L,
                4000, 31, utxo, "100 USDT", "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3",
                "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", "0.0004 BTC");

        TransactionSignedResult result = transaction.signTransaction(Constants.TESTNET, Path.BITCOIN_TESTNET_PATH);
        return result;
    }*/

    public static TransactionSignedResult testUsdtSegwitTxSign() {

        TransactionSignedResult signedResult = null;

        try {

            btcapi.Btc.Utxo utxo0 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("9baf6fd0e560f9f199f4879c23cb73b9c4affb54a1cfdbacb85687efa89f4c78")
                    .setVout(1)
                    .setAmount(21863396)
                    .setAddress("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB")
                    .setScriptPubKey("a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987")
                    .setDerivedPath("0/0")
                    .setSequence(4294967295l)
                    .build();

            btcapi.Btc.BtcTxReq btcTxReq = btcapi.Btc.BtcTxReq.newBuilder()
                    .setTo("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3")
                    .setChangeAddressIndex(0)
                    .setAmount(10000000000L)
                    .setFee(4000)
                    .addUnspents(utxo0)
                    .setNetwork("TESTNET")
                    .setPathPrefix(Path.BITCOIN_SEGWIT_TESTNET_PATH)
                    .setPropertyId(31)
                    .build();

            Any any = Any.newBuilder()
                    .setValue(btcTxReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("btc_usdt_segwit_tx_sign")
                    .setParam(any)
                    .build();
            String hex = NumericUtil.bytesToHex(action.toByteArray());

            // clear_err
            RustApi.INSTANCE.clear_err();

            String result = RustApi.INSTANCE.call_imkey_api(hex);

            String error = RustApi.INSTANCE.get_last_err_message();
            if(!"".equals(error) && null != error) {
                api.Api.Response errorResponse = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
                Boolean isSuccess = errorResponse.getIsSuccess();
                if(!isSuccess) {
                    LogUtil.d("异常： " + errorResponse.getError());

                }
            } else {
                btcapi.Btc.BtcSegwitTxRes response = btcapi.Btc.BtcSegwitTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                String signature = response.getWitnessTxData();
                String tx_hash = response.getTxHash();
                String wtx_id = response.getWtxHash();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("signature：" + signature);
                LogUtil.d("tx_hash：" + tx_hash);
                LogUtil.d("wtx_id：" + wtx_id);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                signedResult = new TransactionSignedResult(signature, tx_hash, wtx_id);
            }
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }

        return signedResult;
    }


    /*public static TransactionSignedResult testUsdtSegwitTxSign() {
        ArrayList<ImKeyOmniTransaction.UTXO> utxo = new ArrayList<>();

        utxo.add(new ImKeyOmniTransaction.UTXO(
                "9baf6fd0e560f9f199f4879c23cb73b9c4affb54a1cfdbacb85687efa89f4c78", 1,
                21863396, "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB",
                "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987",
                "0/0"));

        ImKeyOmniTransaction transaction = new ImKeyOmniTransaction("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3", 10000000000L,
                4000, 31, utxo, "100 USDT", "moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3",
                "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB", "0.0004 BTC");
        TransactionSignedResult result = transaction.signSegWitTransaction(Constants.TESTNET, Path.BITCOIN_SEGWIT_TESTNET_PATH);

        return result;
    }*/
}
