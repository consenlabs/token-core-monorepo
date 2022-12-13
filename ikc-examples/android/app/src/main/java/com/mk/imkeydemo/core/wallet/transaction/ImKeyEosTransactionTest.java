package com.mk.imkeydemo.core.wallet.transaction;

import android.content.Context;

import com.google.protobuf.Any;
import com.mk.imkeydemo.keycore.Path;
import com.mk.imkeydemo.keycore.RustApi;
import com.mk.imkeydemo.keycore.TxMultiSignResult;
import com.mk.imkeydemo.utils.NumericUtil;
import com.mk.imkeydemo.utils.ResourcesManager;


import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import im.imkey.imkeylibrary.common.Messages;
import im.imkey.imkeylibrary.exception.ImkeyException;
import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;

public class ImKeyEosTransactionTest {

    //contains failCount、successCount、failed test case name
    public static Map<String, Object> result = new HashMap<String, Object>();

    public static Map<String, Object> testEosTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "eostransactiontest");
        Iterator<String> keys = testcases.keys();
        try {


            while (keys.hasNext()) {

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);

                eosapi.Eos.EosSignData.Builder data = eosapi.Eos.EosSignData.newBuilder();

                JSONArray publicKeys = testcase.getJSONArray("publicKeys");
                for (int i = 0; i < publicKeys.length(); i++) {
                    JSONObject publicKeyOjb = publicKeys.getJSONObject(i);
                    data.addPubKeys(publicKeyOjb.getString("publicKey"));
                }

                JSONObject pre = testcase.getJSONObject("preview");
                String paymentDis = pre.getString("payment");
                String receiverDis = pre.getString("receiver");
                String senderDis = pre.getString("sender");

                data
                        .setTxData(testcase.getString("txHex"))
                        .setChainId(testcase.getString("chainId"))
                        .setTo(receiverDis)
                        .setFrom(senderDis)
                        .setPayment(paymentDis)
                        .build();

                eosapi.Eos.EosTxReq eosTxReq = eosapi.Eos.EosTxReq.newBuilder()
                        .setPath(Path.EOS_LEDGER)
                        .addSignDatas(data)
                        .build();

                Any any = Any.newBuilder()
                        .setValue(eosTxReq.toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("eos_tx_sign")
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

                        eosapi.Eos.EosTxRes response = eosapi.Eos.EosTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                        eosapi.Eos.EosSignResult signResult = response.getTransMultiSigns(0);
                        String hash = signResult.getHash();
                        LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                        if(hash.equals(testcase.getString("txHash"))) {
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


    /*public static Map<String, Object> testEosTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "eostransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {
                ArrayList<ImKeyBitcoinTransaction.UTXO> utxo = new ArrayList<>();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);

                List<String> publicKeyList = new ArrayList<String>();
                JSONArray publicKeys = testcase.getJSONArray("publicKeys");
                for (int i = 0; i < publicKeys.length(); i++) {
                    JSONObject publicKeyOjb = publicKeys.getJSONObject(i);
                    publicKeyList.add(publicKeyOjb.getString("publicKey"));
                }
                ImKeyEOSTransaction.ToSignObj toSignObj = new ImKeyEOSTransaction.ToSignObj();
                toSignObj.setPublicKeys(publicKeyList);
                toSignObj.setTxHex(testcase.getString("txHex"));

                List<ImKeyEOSTransaction.ToSignObj> toSignObjs = new ArrayList<>();
                toSignObjs.add(toSignObj);
                ImKeyEOSTransaction eosTransaction = new ImKeyEOSTransaction(toSignObjs);

                String chainId = testcase.getString("chainId");
                JSONObject pre = testcase.getJSONObject("preview");
                String paymentDis = pre.getString("payment");
                String receiverDis = pre.getString("receiver");
                String senderDis = pre.getString("sender");

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {
                        List<TxMultiSignResult> signResults = eosTransaction.signTransactions(chainId, receiverDis, senderDis, paymentDis, Path.EOS_LEDGER);
                        String txHash = signResults.get(0).getTxHash();
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

    public static List<TxMultiSignResult> testEosTxSign() {

        List<TxMultiSignResult> signResults = new ArrayList<TxMultiSignResult>();

        try {

            eosapi.Eos.EosSignData data = eosapi.Eos.EosSignData.newBuilder()
                    .setTxData("c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00")
                    .addPubKeys("EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF")
                    .setChainId("aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906")
                    .setTo("bbbb5555bbbb")
                    .setFrom("liujianmin12")
                    .setPayment("undelegatebw 0.0100 EOS")
                    .build();

            eosapi.Eos.EosTxReq eosTxReq = eosapi.Eos.EosTxReq.newBuilder()
                    .setPath(Path.EOS_LEDGER)
                    .addSignDatas(data)
                    .build();

            Any any = Any.newBuilder()
                    .setValue(eosTxReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("eos_tx_sign")
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
                eosapi.Eos.EosTxRes response = eosapi.Eos.EosTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                eosapi.Eos.EosSignResult signResult = response.getTransMultiSigns(0);
                String hash = signResult.getHash();
                List signs = signResult.getSignsList();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("hash：" + hash);
                LogUtil.d("signs：" + signs.get(0));
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                TxMultiSignResult signedResult = new TxMultiSignResult(hash, signs);
                signResults.add(signedResult);
            }
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }
        return signResults;
    }

    /*public static List<TxMultiSignResult> testEosTxSign() {
        List<ImKeyEOSTransaction.ToSignObj> toSignObjs = new ArrayList<>();
        ImKeyEOSTransaction.ToSignObj toSignObj = new ImKeyEOSTransaction.ToSignObj();
        toSignObj.setPublicKeys(Collections.singletonList("EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF"));
        toSignObj.setTxHex("c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00");
        toSignObjs.add(toSignObj);
        ImKeyEOSTransaction eosTransaction = new ImKeyEOSTransaction(toSignObjs);
        String chainIdEos = "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906";
        String to = "bbbb5555bbbb";
        String from = "liujianmin12";
        String payment = "undelegatebw 0.0100 EOS";
        List<TxMultiSignResult> signResults = eosTransaction.signTransactions(chainIdEos, to, from, payment, Path.EOS_LEDGER);
        return signResults;
    }*/

    public static String testEosMsgSign() {

        String signature = null;

        try {

            String publiKey = "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF";

            eosapi.Eos.EosMessageSignReq eosMessageSignReq = eosapi.Eos.EosMessageSignReq.newBuilder()
                    .setPath(Path.EOS_LEDGER)
                    .setData("imKey2019")
                    .setIsHex(false)
                    .setPubkey(publiKey)
                    .build();

            Any any = Any.newBuilder()
                    .setValue(eosMessageSignReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("eos_message_sign")
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
                eosapi.Eos.EosMessageSignRes response = eosapi.Eos.EosMessageSignRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                signature = response.getSignature();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("signature：" + signature);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
            }
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }
        return signature;

        /*String PUBLIC_KEY = "EOS88XhiiP7Cu5TmAUJqHbyuhyYgd6sei68AU266PyetDDAtjmYWF";
        return new Eos().eosEcSign("imKey2019", false, PUBLIC_KEY,Path.EOS_LEDGER);
        */
    }
}
