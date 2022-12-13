package com.mk.imkeydemo.core.wallet.transaction;

import com.google.protobuf.Any;
import com.mk.imkeydemo.keycore.RustApi;
import com.mk.imkeydemo.keycore.TransactionSignedResult;
import com.mk.imkeydemo.utils.NumericUtil;

import org.json.JSONObject;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;

public class ImKeyFilecoinTransactionTest {

    //contains failCount、successCount、failed test case name
    public static Map<String, Object> result = new HashMap<String, Object>();


    public static TransactionSignedResult testFilecoinTxSign() {

        TransactionSignedResult signResults = null;

        try {

            filecoinapi.Filecoin.UnsignedMessage message = filecoinapi.Filecoin.UnsignedMessage.newBuilder()
                    .setTo("f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba")
                    .setFrom("f1o2ph66tg7o7obyrqa7eiwiinrltauzxitkuk4ay")
                    .setNonce(1)
                    .setValue("100000")
                    .setGasLimit(1)
                    .setGasFeeCap("1")
                    .setGasPremium("1")
                    .setMethod(0)
                    .setParams("")
                    .build();
            filecoinapi.Filecoin.FilecoinTxReq txReq = filecoinapi.Filecoin.FilecoinTxReq.newBuilder()
                    .setMessage(message)
                    .setPath("m/44'/461'/0/0/0")
                    .setNetwork("MAINNET")
                    .setPaymentDis("1 FILECOIN")
                    .setToDis("f1d2xrzcslx7xlbbylc5c3d5lvandqw4iwl6epxba")
                    .setFromDis("f1o2ph66tg7o7obyrqa7eiwiinrltauzxitkuk4ay")
                    .setFeeDis("0.1 FILECOIN")
                    .build();


            Any any = Any.newBuilder()
                    .setValue(txReq.toByteString())
                    .build();

            api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                    .setMethod("filecoin_tx_sign")
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
                filecoinapi.Filecoin.FilecoinTxRes response = filecoinapi.Filecoin.FilecoinTxRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                String cid = response.getCid();
                int type = response.getSignature().getType();
                String signature = response.getSignature().getData();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("cid：" + cid);
                LogUtil.d("type：" + type);
                LogUtil.d("signature：" + signature);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

                signResults = new TransactionSignedResult(signature, cid);
            }
        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }
        return signResults;
    }
}
