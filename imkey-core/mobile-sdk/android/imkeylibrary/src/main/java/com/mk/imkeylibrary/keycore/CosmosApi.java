package com.mk.imkeylibrary.keycore;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.mk.imkeylibrary.utils.NumericUtil;

import cosmosapi.Cosmos;

public class CosmosApi {
    public static String getAddress(String path) {
        Cosmos.CosmosAddressReq req = Cosmos.CosmosAddressReq.newBuilder()
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("cosmos_get_address")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Cosmos.CosmosAddressRes result = null;
        try {
            result = Cosmos.CosmosAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static String displayAddress(String path) {
        Cosmos.CosmosAddressReq req = Cosmos.CosmosAddressReq.newBuilder()
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("cosmos_register_address")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());
        byte[] bytes = Api.getInstance().callApi(hex);
        Cosmos.CosmosAddressRes result = null;
        try {
            result = Cosmos.CosmosAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static Cosmos.CosmosTxRes signTx(Cosmos.CosmosTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("cosmos_tx_sign")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Cosmos.CosmosTxRes result = null;
        try {
            result = Cosmos.CosmosTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }
}
