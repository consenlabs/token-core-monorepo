package com.mk.imkeylibrary.keycore;

import com.google.protobuf.Any;
import com.google.protobuf.InvalidProtocolBufferException;
import com.mk.imkeylibrary.utils.NumericUtil;

import btcapi.Btc;

public class BtcApi {
    public static final String NETWORK_MAINNET = "MAINNET";
    public static final String NETWORK_TESTNET = "TESTNET";

    public static String getAddress(String network,String path){
        btcapi.Btc.BtcAddressReq req = btcapi.Btc.BtcAddressReq.newBuilder()
                .setNetwork(network)
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_get_address")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcAddressRes result = null;
        try {
            result = Btc.BtcAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static String displayAddress(String network,String path){
        btcapi.Btc.BtcAddressReq req = btcapi.Btc.BtcAddressReq.newBuilder()
                .setNetwork(network)
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_register_address")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcAddressRes result = null;
        try {
            result = Btc.BtcAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static String getSegWitAddress(String network,String path){
        btcapi.Btc.BtcAddressReq req = btcapi.Btc.BtcAddressReq.newBuilder()
                .setNetwork(network)
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_get_setwit_address")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcAddressRes result = null;
        try {
            result = Btc.BtcAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static String displaySegWitAddress(String network,String path){
        btcapi.Btc.BtcAddressReq req = btcapi.Btc.BtcAddressReq.newBuilder()
                .setNetwork(network)
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_register_segwit_address")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcAddressRes result = null;
        try {
            result = Btc.BtcAddressRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getAddress();
    }

    public static String getXpub(String network,String path){
        Btc.BtcXpubReq req = Btc.BtcXpubReq.newBuilder()
                .setNetwork(network)
                .setPath(path)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_get_xpub")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcXpubRes result = null;
        try {
            result = Btc.BtcXpubRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result.getXpub();
    }

    public static Btc.BtcTxRes signTx(Btc.BtcTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_tx_sign")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcTxRes result = null;
        try {
            result = Btc.BtcTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }

    public static Btc.BtcSegwitTxRes signSwgWitTx(Btc.BtcSegwitTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_segwit_tx_sign")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcSegwitTxRes result = null;
        try {
            result = Btc.BtcSegwitTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }

    public static Btc.BtcTxRes signUsdtTx(Btc.BtcTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_usdt_tx_sign")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcTxRes result = null;
        try {
            result = Btc.BtcTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }

    public static Btc.BtcSegwitTxRes signUsdtSegWitTx(Btc.BtcSegwitTxReq req){
        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("btc_segwit_tx_sign")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        byte[] bytes = Api.getInstance().callApi(hex);
        Btc.BtcSegwitTxRes result = null;
        try {
            result = Btc.BtcSegwitTxRes.parseFrom(bytes);
        } catch (InvalidProtocolBufferException e) {
            e.printStackTrace();
        }

        return result;
    }
}
