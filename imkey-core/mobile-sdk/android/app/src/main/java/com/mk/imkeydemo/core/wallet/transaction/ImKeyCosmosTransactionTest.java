package com.mk.imkeydemo.core.wallet.transaction;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

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
import com.mk.imkeylibrary.keycore.RustApi;
import com.mk.imkeylibrary.utils.ByteUtil;
import com.mk.imkeylibrary.utils.LogUtil;
import com.mk.imkeylibrary.utils.NumericUtil;

public class ImKeyCosmosTransactionTest {

    //contains failCount、successCount、failed test case name
    public static Map<String, Object> result = new HashMap<String, Object>();

    public static Map<String, Object> testCosmosTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "cosmostransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {


                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONObject fee = testcase.getJSONObject("fee");

                JSONArray amount = fee.getJSONArray("amount");

                //定义SignData
                cosmosapi.Cosmos.SignData.Builder signDataBuilder = cosmosapi.Cosmos.SignData.newBuilder();

                //设置fee
                cosmosapi.Cosmos.StdFee.Builder stdFeeBuilder = cosmosapi.Cosmos.StdFee.newBuilder();
                for (int i = 0; i < amount.length(); i++) {

                    JSONObject amountOjb = amount.getJSONObject(i);
                    String feeAmount = amountOjb.getString("amount");
                    String feeDenom = amountOjb.getString("denom");
                    cosmosapi.Cosmos.Coin coin = cosmosapi.Cosmos.Coin.newBuilder()
                            .setAmount(feeAmount)
                            .setDenom(feeDenom)
                            .build();
                    stdFeeBuilder.addAmount(coin);
                }
                String gas = fee.getString("gas");
                stdFeeBuilder.setGas(gas);
                signDataBuilder.setFee(stdFeeBuilder.build());

                // 设置msg
                List<Map<String, Object>> msgList = new ArrayList<Map<String, Object>>();
                JSONArray msg = testcase.getJSONArray("msg");

                for (int i = 0; i < msg.length(); i++) {
                    JSONObject msgOjb = msg.getJSONObject(i);

                    //定义msg
                    cosmosapi.Cosmos.Msg.Builder msgBuilder = cosmosapi.Cosmos.Msg.newBuilder();

                    // type
                    Map<String, Object> msgMap = new HashMap<>();
                    String type = msgOjb.getString("type");
                    msgBuilder.setType(type);

                    // value
                    cosmosapi.Cosmos.MsgValue.Builder msgValueBuilder = cosmosapi.Cosmos.MsgValue.newBuilder();

                    JSONObject value = msgOjb.getJSONObject("value");
                    JSONArray amountArray = value.getJSONArray("amount");

                    // value-amount
                    for (int j = 0; j < amountArray.length(); j++) {

                        JSONObject amountOjb = amountArray.getJSONObject(j);
                        String msgAmount = amountOjb.getString("amount");
                        String denom = amountOjb.getString("denom");

                        cosmosapi.Cosmos.Coin amountCoin = cosmosapi.Cosmos.Coin.newBuilder()
                                .setAmount(msgAmount)
                                .setDenom(denom)
                                .build();

                        msgValueBuilder.addAmount(amountCoin);
                    }

                    // value- address
                    if(value.has("to_address")) {
                        String to_address = value.getString("to_address");
                        String from_address = value.getString("from_address");
                        msgValueBuilder.putAddresses("to_address", to_address);
                        msgValueBuilder.putAddresses("from_address", from_address);
                    } else {
                        String delegator_address = value.getString("delegator_address");
                        String validator_address = value.getString("validator_address");
                        msgValueBuilder.putAddresses("delegator_address", delegator_address);
                        msgValueBuilder.putAddresses("validator_address", validator_address);
                    }
                    msgBuilder.setValue(msgValueBuilder.build());

                    signDataBuilder.addMsgs(msgBuilder.build());
                }

                String memoString = testcase.getString("memo");
                String accountNumber = testcase.getString("accountNumber");
                String chainId = testcase.getString("chainId");
                String sequence = testcase.getString("sequence");

                JSONObject pre = testcase.getJSONObject("preview");
                String paymentDis = pre.getString("payment");
                String receiverDis = pre.getString("receiver");
                String senderDis = pre.getString("sender");
                String feeDis = pre.getString("fee");


                com.google.protobuf.StringValue memo = com.google.protobuf.StringValue.newBuilder()
                    .setValue(memoString).build();

                signDataBuilder
                        .setAccountNumber(accountNumber)
                        .setChainId(chainId)
                        .setMemo(memo)
                        .setSequence(sequence)
                        .build();


                cosmosapi.Cosmos.CosmosTxReq cosmosTxReq = cosmosapi.Cosmos.CosmosTxReq.newBuilder()
                        .setSignData(signDataBuilder.build())
                        .setPath(Path.COSMOS_LEDGER)
                        .setPaymentDis(paymentDis)
                        .setToDis(receiverDis)
                        .setFromDis(senderDis)
                        .setFeeDis(feeDis)
                        .build();

                Any any = Any.newBuilder()
                        .setValue(cosmosTxReq.toByteString())
                        .build();

                api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                        .setMethod("cosmos_tx_sign")
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

                        String error = RustApi.INSTANCE.get_last_err_message();
                        if(!"".equals(error) && null != error) {
                            api.Api.Response errorResponse = api.Api.Response.parseFrom(ByteUtil.hexStringToByteArray(error));
                            Boolean isSuccess = errorResponse.getIsSuccess();
                            if(!isSuccess) {
                                LogUtil.d("异常： " + errorResponse.getError());

                            }
                        } else {
                            cosmosapi.Cosmos.CosmosTxRes response = cosmosapi.Cosmos.CosmosTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                            String signData = response.getTxData();
                            LogUtil.d("signature：" + signData);
                            LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                            JSONObject jsonObject = new JSONObject(signData);
                            JSONArray signatures = jsonObject.getJSONArray("signatures");
                            JSONObject signatureObj = signatures.getJSONObject(0);
                            String signature = signatureObj.getString("signature");
                            JSONArray signaturesExp = testcase.getJSONArray("signatures");
                            JSONObject signatureExpObj = signaturesExp.getJSONObject(0);
                            String signatureExp = signatureExpObj.getString("signature");

                            if(signature.equals(signatureExp)) {
                                successCount ++;
                                LogUtil.e("×××××××××××××××××××××××××××××××××××成功×××××××××××××××××××××××××××××××××××××××××××××××");
                            } else {
                                failedCaseName.add(key);
                                failCount++;
                            }
                            retry = false;

                        }

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


    /*public static Map<String, Object> testCosmosTxSign(Context context) {
        int failCount = 0;
        int successCount = 0;
        ArrayList<String> failedCaseName = new ArrayList<>();

        JSONObject testcases = ResourcesManager.getFromRaw(context, "cosmostransactiontest");
        Iterator<String> keys = testcases.keys();
        try {
            while (keys.hasNext()) {
                ArrayList<ImKeyBitcoinTransaction.UTXO> utxo = new ArrayList<>();

                String key = keys.next();
                JSONObject testcase = testcases.getJSONObject(key);
                JSONObject fee = testcase.getJSONObject("fee");

                List<Coin> amountList = new ArrayList<Coin>();
                JSONArray amount = fee.getJSONArray("amount");
                for (int i = 0; i < amount.length(); i++) {

                    JSONObject amountOjb = amount.getJSONObject(i);
                    Long feeAmount = amountOjb.getLong("amount");
                    String feeDenom = amountOjb.getString("denom");

                    Coin coin = new Coin(feeDenom, feeAmount);
                    amountList.add(coin);
                }
                Long gas = fee.getLong("gas");
                StdFee stdFee = new StdFee(amountList, gas);

                List<Map<String, Object>> msgList = new ArrayList<Map<String, Object>>();
                JSONArray msg = testcase.getJSONArray("msg");
                for (int i = 0; i < msg.length(); i++) {
                    JSONObject msgOjb = msg.getJSONObject(i);

                    Map<String, Object> msgMap = new HashMap<>();
                    String type = msgOjb.getString("type");
                    msgMap.put("type", type);

                    //设置value
                    JSONObject value = msgOjb.getJSONObject("value");
                    Map<String, Object> arbMsg = new HashMap<>();
                    List<Map<String, Object>> msgAmountList = new ArrayList<Map<String, Object>>();
                    JSONArray amountArray = value.getJSONArray("amount");
                    for (int j = 0; j < amountArray.length(); j++) {

                        JSONObject amountOjb = amountArray.getJSONObject(j);
                        Long msgAmount = amountOjb.getLong("amount");
                        String denom = amountOjb.getString("denom");

                        Map<String, Object> amountMap = new HashMap<>();
                        amountMap.put("denom", denom);
                        amountMap.put("amount", msgAmount);
                        msgAmountList.add(amountMap);
                    }

                    if(value.has("to_address")) {
                        String to_address = value.getString("to_address");
                        String from_address = value.getString("from_address");

                        arbMsg.put("to_address", to_address);
                        arbMsg.put("from_address", from_address);
                    } else {
                        String delegator_address = value.getString("delegator_address");
                        String validator_address = value.getString("validator_address");

                        arbMsg.put("delegator_address", delegator_address);
                        arbMsg.put("validator_address", validator_address);
                    }

                    arbMsg.put("amount", msgAmountList);

                    msgMap.put("value", arbMsg);
                    msgList.add(msgMap);
                }

                String memo = testcase.getString("memo");
                Long accountNumber = testcase.getLong("accountNumber");
                String chainId = testcase.getString("chainId");
                Long sequence = testcase.getLong("sequence");

                ImKeyCosmosTransaction transaction = new ImKeyCosmosTransaction(accountNumber, chainId, stdFee, memo, msgList, sequence);

                JSONObject pre = testcase.getJSONObject("preview");
                String paymentDis = pre.getString("payment");
                String receiverDis = pre.getString("receiver");
                String senderDis = pre.getString("sender");
                String feeDis = pre.getString("fee");

                Boolean retry = true;
                int tryCount = 0;
                while(retry) {
                    tryCount ++;
                    try {

                        TransactionSignedResult txSignResult = transaction.signTransaction("0", Path.COSMOS_LEDGER, paymentDis,receiverDis,senderDis,feeDis);
                        JSONObject jsonObject = new JSONObject(txSignResult.getSignedTx());
                        JSONArray signatures = jsonObject.getJSONArray("signatures");
                        JSONObject signatureObj = signatures.getJSONObject(0);
                        String signature = signatureObj.getString("signature");

                        JSONArray signaturesExp = testcase.getJSONArray("signatures");
                        JSONObject signatureExpObj = signaturesExp.getJSONObject(0);
                        String signatureExp = signatureExpObj.getString("signature");

                        if(signature.equals(signatureExp)) {
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

    public static TransactionSignedResult testCosmosTxSign() {


        TransactionSignedResult txSignResult = null;

        try {

            String to = "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt";
            String from = "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992";
            String payment = "0.001 ATOM";
            String fee = "0.00075 atom";

            cosmosapi.Cosmos.Coin amount = cosmosapi.Cosmos.Coin.newBuilder()
                    .setAmount("10")
                    .setDenom("atom")
                    .build();

            cosmosapi.Cosmos.MsgValue msgValue = cosmosapi.Cosmos.MsgValue.newBuilder()
                    .addAmount(amount)
                    .putAddresses("delegator_address", "cosmos1y0a8sc5ayv52f2fm5t7hr2g88qgljzk4jcz78f")
                    .putAddresses("validator_address", "cosmosvaloper1zkupr83hrzkn3up5elktzcq3tuft8nxsmwdqgp")
                    .build();

            cosmosapi.Cosmos.Msg msg = cosmosapi.Cosmos.Msg.newBuilder()
                    .setType("cosmos-sdk/MsgDelegate")
                    .setValue(msgValue)
                    .build();

            cosmosapi.Cosmos.Coin coin = cosmosapi.Cosmos.Coin.newBuilder()
                    .setAmount("0")
                    .setDenom("")
                    .build();

            cosmosapi.Cosmos.StdFee stdFee= cosmosapi.Cosmos.StdFee.newBuilder()
                    .addAmount(coin)
                    .setGas("21906")
                    .build();

            /*com.google.protobuf.StringValue memo = com.google.protobuf.StringValue.newBuilder()
                    .setValue("test").build();*/



            cosmosapi.Cosmos.SignData signData = cosmosapi.Cosmos.SignData.newBuilder()
                    .setAccountNumber("1")
                    .setChainId("tendermint_test")
                    .setFee(stdFee)
                    //.setMemo(memo)
                    .addMsgs(msg)
                    .setSequence("0")
                    .build();


            cosmosapi.Cosmos.CosmosTxReq cosmosTxReq = cosmosapi.Cosmos.CosmosTxReq.newBuilder()
                    .setSignData(signData)
                    .setPath(Path.COSMOS_LEDGER)
                    //.setPaymentDis(payment)
                    .setToDis(to)
                    .setFromDis(from)
                    .setFeeDis(fee)
                    .build();

            Any any = Any.newBuilder()
                    .setValue(cosmosTxReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("cosmos_tx_sign")
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
                cosmosapi.Cosmos.CosmosTxRes response = cosmosapi.Cosmos.CosmosTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                String signature = response.getTxData();
                String tx_hash = response.getTxHash();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("signature：" + signature);
                LogUtil.d("tx_hash：" + tx_hash);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                txSignResult = new TransactionSignedResult(tx_hash, signature);
            }
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }
        return txSignResult;

    }

    /*public static TransactionSignedResult testCosmosTxSign() {
        Coin coin = new Coin("", 0);
        StdFee stdFee = new StdFee(Collections.singletonList(coin), 21906);
        HashMap<String, Object> arbMsg = new HashMap<>();

        arbMsg = new HashMap<>();
        arbMsg.put("delegator_address", "cosmos1y0a8sc5ayv52f2fm5t7hr2g88qgljzk4jcz78f");
        arbMsg.put("validator_address", "cosmosvaloper1zkupr83hrzkn3up5elktzcq3tuft8nxsmwdqgp");
        Map<String, Object> amount = new HashMap<>();
        amount.put("denom", "atom");
        amount.put("amount", "10");

        arbMsg.put("amount", Collections.singletonList(amount));
        Map<String, Object> msgMap = new HashMap<>();
        msgMap.put("type", "cosmos-sdk/MsgDelegate");
        msgMap.put("value", arbMsg);
        ImKeyCosmosTransaction transaction = new ImKeyCosmosTransaction(1, "tendermint_test", stdFee, null, Collections.singletonList(msgMap), 0);

        String to = "cosmos1yeckxz7tapz34kjwnjxvmxzurerquhtrmxmuxt";
        String from = "cosmos1ajz9y0x3wekez7tz2td2j6l2dftn28v26dd992";
        String payment = "0.001 ATOM";
        String fee = "0.00075 atom";
        TransactionSignedResult txSignResult = transaction.signTransaction("0", Path.COSMOS_LEDGER, null,to,from,fee);
        return txSignResult;
    }*/


}
