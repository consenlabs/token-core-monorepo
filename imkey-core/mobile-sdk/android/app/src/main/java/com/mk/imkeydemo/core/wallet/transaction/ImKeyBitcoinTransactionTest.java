package com.mk.imkeydemo.core.wallet.transaction;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.google.protobuf.Any;
import com.google.protobuf.ByteString;
import com.mk.imkeydemo.utils.ResourcesManager;
import com.mk.imkeylibrary.common.Constants;
import com.mk.imkeylibrary.common.Messages;
import com.mk.imkeylibrary.common.Path;
import com.mk.imkeylibrary.common.TransactionSignedResult;
import com.mk.imkeylibrary.exception.ImkeyException;
import com.mk.imkeylibrary.keycore.RustApi;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;


public class ImKeyBitcoinTransactionTest {

    //contains failCount、successCount、failed test case name
    public static Map<String, Object> result = new HashMap<String, Object>();

    public static Map<String, Object> testBitcoinSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "btctransactiontest");
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


                ByteString extraData = ByteString.copyFrom("1234".getBytes());

                builder
                        .setTo(testcase.getString("to"))
                        .setChangeAddressIndex(testcase.getInt("changeIdx"))
                        .setAmount(testcase.getLong("amount"))
                        .setFee(testcase.getLong("fee"))
                        //.setExtraData(extraData)
                        .setNetwork(Constants.MAINNET)
                        .setPathPrefix(Path.BTC_PATH_PREFIX)
                        .build();


                Any any = Any.newBuilder()
                        .setValue(builder.build().toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("btc_tx_sign")
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

    /*public static Map<String, Object> testBitcoinSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "btctransactiontest");
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

                ImKeyBitcoinTransaction transaction = new ImKeyBitcoinTransaction(
                        testcase.getString("to"),
                        testcase.getInt("changeIdx"),
                        testcase.getLong("amount"),
                        testcase.getLong("fee"),
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

    public static Map<String, Object> testBitcoinSegwitSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "btcsegwittransactiontest");
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
                        .setChangeAddressIndex(testcase.getInt("changeIdx"))
                        .setAmount(testcase.getLong("amount"))
                        .setFee(testcase.getLong("fee"))
                        //.setExtraData(extraData)
                        .setNetwork(Constants.MAINNET)
                        .setPathPrefix(Path.BTC_SEGWIT_PATH_PREFIX)
                        .build();


                Any any = Any.newBuilder()
                        .setValue(builder.build().toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("btc_segwit_tx_sign")
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

    /*
    public static Map<String, Object> testBitcoinSegwitSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "btcsegwittransactiontest");
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

                ImKeyBitcoinTransaction transaction = new ImKeyBitcoinTransaction(
                        testcase.getString("to"),
                        testcase.getInt("changeIdx"),
                        testcase.getLong("amount"),
                        testcase.getLong("fee"),
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


    public static TransactionSignedResult testBitcoinSign() {

        TransactionSignedResult signedResult = null;

        try {

            btcapi.Btc.Utxo utxo0 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a")
                    .setVout(0)
                    .setAmount(200000000)
                    .setAddress("mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC")
                    .setScriptPubKey("76a914118c3123196e030a8a607c22bafc1577af61497d88ac")
                    .setDerivedPath("0/22")
                    .setSequence(4294967295l)
                    .build();

            btcapi.Btc.Utxo utxo1 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531")
                    .setVout(1)
                    .setAmount(200000000)
                    .setAddress("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
                    .setScriptPubKey("76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac")
                    .setDerivedPath("0/0")
                    .setSequence(4294967295l)
                    .build();

            btcapi.Btc.Utxo utxo2 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9")
                    .setVout(0)
                    .setAmount(200000000)
                    .setAddress("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
                    .setScriptPubKey("76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac")
                    .setDerivedPath("0/0")
                    .setSequence(4294967295l)
                    .build();


            btcapi.Btc.Utxo utxo3 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9")
                    .setVout(1)
                    .setAmount(200000000)
                    .setAddress("mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN")
                    .setScriptPubKey("76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac")
                    .setDerivedPath("0/0")
                    .setSequence(4294967295l)
                    .build();

            ByteString extraData = ByteString.copyFrom(ByteUtil.hexStringToByteArray("0200000080a10bc28928f4c17a287318125115c3f098ed20a8237d1e8e4125bc25d1be99752adad0a7b9ceca853768aebb6965eca126a62965f698a0c1bc43d83db632ad7f717276057e6012afa99385"));

            btcapi.Btc.BtcTxReq btcTxReq = btcapi.Btc.BtcTxReq.newBuilder()
                    .setTo("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3")
                    .setChangeAddressIndex(53)
                    .setAmount(799988000)
                    .setFee(10000)
                    .addUnspents(utxo0)
                    .addUnspents(utxo1)
                    .addUnspents(utxo2)
                    .addUnspents(utxo3)
                    .setExtraData(extraData)
                    .setNetwork("TESTNET")
                    .setPathPrefix(Path.BITCOIN_TESTNET_PATH)
                    .build();


            Any any = Any.newBuilder()
                    .setValue(btcTxReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("btc_tx_sign")
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
        /*ArrayList<ImKeyBitcoinTransaction.UTXO> utxo = new ArrayList<>();

//        utxo.add(new ImKeyBitcoinTransaction.UTXO(
//                "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a", 0,
//                200000000, "1Fj93kpLwM1KgTN6C75Z5Bokhays4MmJae",
//                "76a914a189f2f7836812aa7a0e36e28a20a10e64010bf688ac",
//                "0/22"));
//        utxo.add(new ImKeyBitcoinTransaction.UTXO(
//                "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531", 1,
//                200000000, "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
//                "76a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788ac",
//                "0/0"));
//        utxo.add(new ImKeyBitcoinTransaction.UTXO(
//                "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9", 0,
//                200000000, "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
//                "76a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788ac",
//                "0/0"));
//        utxo.add(new ImKeyBitcoinTransaction.UTXO(
//                "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9", 1,
//                200000000, "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
//                "76a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788ac",
//                "0/0"));
//
//        ImKeyBitcoinTransaction tran = new ImKeyBitcoinTransaction("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV", 53,
//                750000000, 502130, utxo, "0.0001 BT", "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
//                "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy", "0.00007945 BTC");
//        TransactionSignedResult result = tran.signTransaction(Constants.MAINNET, Path.BTC_PATH_PREFIX);
//


        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a", 0,
                200000000, "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC",
                "76a914118c3123196e030a8a607c22bafc1577af61497d88ac",
                "0/22"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531", 1,
                200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9", 0,
                200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9", 1,
                200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));
        HashMap<String, Object> extra = new HashMap<>();
        extra.put("opReturn", "1234");

        ImKeyBitcoinTransaction tran = new ImKeyBitcoinTransaction("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3", 53,
                799988000, 10000, utxo, extra,"0.0001 BT", "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
                "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy", "0.00007945 BTC");
        TransactionSignedResult result = tran.signTransaction(Constants.TESTNET, Path.BITCOIN_TESTNET_PATH);

        return result;*/
    }

/*
    public static TransactionSignedResult testBitcoinSign() {

        ArrayList<ImKeyBitcoinTransaction.UTXO> utxo = new ArrayList<>();

        *//*utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a", 0,
                200000000, "1Fj93kpLwM1KgTN6C75Z5Bokhays4MmJae",
                "76a914a189f2f7836812aa7a0e36e28a20a10e64010bf688ac",
                "0/22"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531", 1,
                200000000, "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
                "76a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788ac",
                "0/0"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9", 0,
                200000000, "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
                "76a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788ac",
                "0/0"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9", 1,
                200000000, "12z6UzsA3tjpaeuvA2Zr9jwx19Azz74D6g",
                "76a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788ac",
                "0/0"));

        ImKeyBitcoinTransaction tran = new ImKeyBitcoinTransaction("18pMkq6HK5HR36jr7bSd39MpkVCfnP68VV", 53,
                750000000, 502130, utxo, "0.0001 BT", "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
                "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy", "0.00007945 BTC");
        TransactionSignedResult result = tran.signTransaction(Constants.MAINNET, Path.BTC_PATH_PREFIX);
                *//*

        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "983adf9d813a2b8057454cc6f36c6081948af849966f9b9a33e5b653b02f227a", 0,
                200000000, "mh7jj2ELSQUvRQELbn9qyA4q5nADhmJmUC",
                "76a914118c3123196e030a8a607c22bafc1577af61497d88ac",
                "0/22"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "45ef8ac7f78b3d7d5ce71ae7934aea02f4ece1af458773f12af8ca4d79a9b531", 1,
                200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "14c67e92611dc33df31887bbc468fbbb6df4b77f551071d888a195d1df402ca9", 0,
                200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));
        utxo.add(new ImKeyBitcoinTransaction.UTXO(
                "117fb6b85ded92e87ee3b599fb0468f13aa0c24b4a442a0d334fb184883e9ab9", 1,
                200000000, "mkeNU5nVnozJiaACDELLCsVUc8Wxoh1rQN",
                "76a914383fb81cb0a3fc724b5e08cf8bbd404336d711f688ac",
                "0/0"));
        HashMap<String, Object> extra = new HashMap<>();
        extra.put("opReturn", "1234");

        ImKeyBitcoinTransaction tran = new ImKeyBitcoinTransaction("moLK3tBG86ifpDDTqAQzs4a9cUoNjVLRE3", 53,
                799988000, 10000, utxo, extra,"0.0001 BT", "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
                "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy", "0.00007945 BTC");
        TransactionSignedResult result = tran.signTransaction(Constants.TESTNET, Path.BITCOIN_TESTNET_PATH);

        return result;
    }*/


    public static TransactionSignedResult testBitcoinSegwitSign() {



        TransactionSignedResult signedResult = null;

        try {


            btcapi.Btc.Utxo utxo0 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f")
                    .setVout(0)
                    .setAmount(50000)
                    .setAddress("2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB")
                    .setScriptPubKey("a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987")
                    .setDerivedPath("0/0")
                    .setSequence(4294967295l)
                    .build();

            btcapi.Btc.Utxo utxo1 = btcapi.Btc.Utxo.newBuilder()
                    .setTxHash("9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74")
                    .setVout(0)
                    .setAmount(50000)
                    .setAddress("2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf")
                    .setScriptPubKey("a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787")
                    .setDerivedPath("0/1")
                    .setSequence(4294967295l)
                    .build();

            ByteString extraData = ByteString.copyFrom(ByteUtil.hexStringToByteArray("1234"));

            btcapi.Btc.BtcTxReq btcTxReq = btcapi.Btc.BtcTxReq.newBuilder()
                    .setTo("2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp")
                    .setChangeAddressIndex(0)
                    .setAmount(88000)
                    .setFee(10000)
                    .addUnspents(utxo0)
                    .addUnspents(utxo1)
                    .setExtraData(extraData)
                    .setNetwork("TESTNET")
                    .setPathPrefix(Path.BITCOIN_SEGWIT_TESTNET_PATH)
                    .build();

            Any any = Any.newBuilder()
                    .setValue(btcTxReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("btc_segwit_tx_sign")
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

    /*public static TransactionSignedResult testBitcoinSegwitSign() {

        ArrayList<ImKeyBitcoinTransaction.UTXO> utxos = new ArrayList<>();
        utxos.add(new ImKeyBitcoinTransaction.UTXO("c2ceb5088cf39b677705526065667a3992c68cc18593a9af12607e057672717f",
                0, 50000, "2MwN441dq8qudMvtM5eLVwC3u4zfKuGSQAB",
                "a9142d2b1ef5ee4cf6c3ebc8cf66a602783798f7875987",
                "0/0"));
        utxos.add(new ImKeyBitcoinTransaction.UTXO("9ad628d450952a575af59f7d416c9bc337d184024608f1d2e13383c44bd5cd74",
                0, 50000, "2N54wJxopnWTvBfqgAPVWqXVEdaqoH7Suvf",
                "a91481af6d803fdc6dca1f3a1d03f5ffe8124cd1b44787",
                "0/1"));
        HashMap<String, Object> extra = new HashMap<>();
        extra.put("opReturn", "0x1234");
        ImKeyBitcoinTransaction transaction = new ImKeyBitcoinTransaction( "2N9wBy6f1KTUF5h2UUeqRdKnBT6oSMh4Whp",
                0,
                88000,
                10000, utxos,extra,
                "0.0001 BT", "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
                "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy", "0.00007945 BTC");

        *//*utxos.add(new ImKeyBitcoinTransaction.UTXO("cd568d5473f9346626391f5a49e6f25bf06cf9a702ecdcca091803e7978236df",
                1, 7392655, "2NCMNdhzbkv7PBS4WWYwYjRzYF9j633FeaN",
                "a914d1941a330c40ce1096db350954177f6052a001c587",
                "1/6"));

        utxos.add(new ImKeyBitcoinTransaction.UTXO("cd568d5473f9346626391f5a49e6f25bf06cf9a702ecdcca091803e7978236df",
                1, 7392655, "2NCMNdhzbkv7PBS4WWYwYjRzYF9j633FeaN",
                "a914d1941a330c40ce1096db350954177f6052a001c587",
                "1/6"));

        ImKeyBitcoinTransaction transaction = new ImKeyBitcoinTransaction( "mhJnhMJ4RdCcBvm1erEiUGb3BJQ1rPnX6j",
                1,
                1000000,
                169115, utxos,
                "0.0001 BT", "3CVD68V71no5jn2UZpLLq6hASpXu1jrByt",
                "3GrvKsZWbb9ocBaNF7XosFZEKuCVBRSoiy", "0.00007945 BTC");*//*

        TransactionSignedResult result = transaction.signSegWitTransaction(Constants.TESTNET, Path.BITCOIN_SEGWIT_TESTNET_PATH);
        return result;
    }*/
}






