package com.mk.imkeylibrary.keycore;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.mk.imkeylibrary.utils.NumericUtil;
import ethapi.Eth;

public class EthApi {
    public static String getAddress(String path) {
        ethapi.Eth.EthAddressReq req = ethapi.Eth.EthAddressReq.newBuilder()
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eth_get_address")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Eth.EthAddressRes result = null;
        try {
            result = Eth.EthAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static String displayAddress(String path) {
        ethapi.Eth.EthAddressReq req = ethapi.Eth.EthAddressReq.newBuilder()
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eth_register_address")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Eth.EthAddressRes result = null;
        try {
            result = Eth.EthAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static Eth.EthTxRes signTx(Eth.EthTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eth_tx_sign")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Eth.EthTxRes result = null;
        try {
            result = Eth.EthTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }

    public static Eth.EthMessageSignRes signMessage(Eth.EthMessageSignReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eth_tx_sign")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Eth.EthMessageSignRes result = null;
        try {
            result = Eth.EthMessageSignRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }
}
