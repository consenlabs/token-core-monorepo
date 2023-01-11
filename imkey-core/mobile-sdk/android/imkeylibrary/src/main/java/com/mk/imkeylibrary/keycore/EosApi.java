package com.mk.imkeylibrary.keycore;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.mk.imkeylibrary.utils.NumericUtil;

import eosapi.Eos;

public class EosApi {
    public static String getPubKey(String path) {
        Eos.EosPubkeyReq req = Eos.EosPubkeyReq.newBuilder()
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eos_get_pubkey")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Eos.EosPubkeyRes result = null;
        try {
            result = Eos.EosPubkeyRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getPubkey();
    }

    public static String displayPubKey(String path) {
        Eos.EosPubkeyReq req = Eos.EosPubkeyReq.newBuilder()
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eos_register_pubkey")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Eos.EosPubkeyRes result = null;
        try {
            result = Eos.EosPubkeyRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getPubkey();
    }

    public static Eos.EosTxRes signTx(Eos.EosTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eos_tx_sign")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Eos.EosTxRes result = null;
        try {
            result = Eos.EosTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }


    public static Eos.EosMessageSignRes signMessage(Eos.EosMessageSignReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("eos_message_sign")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Eos.EosMessageSignRes result = null;
        try {
            result = Eos.EosMessageSignRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }
}
