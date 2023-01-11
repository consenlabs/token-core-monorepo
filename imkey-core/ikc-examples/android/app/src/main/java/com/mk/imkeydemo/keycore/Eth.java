package com.mk.imkeydemo.keycore;

import com.google.protobuf.Any;
import com.mk.imkeydemo.utils.NumericUtil;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;


public class Eth extends Wallet {

    public String getAddress(String path) {

        String address = null;

        try {

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
                ethapi.Eth.EthAddressRes response = ethapi.Eth.EthAddressRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                address = response.getAddress();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("address：" + address);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

            }

        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }

        return address;

        /*// path校验
        Path.checkPath(path);

        selectApplet();
        String xpub = getEthXpubHex(path, true);
        return publicKeyToAddress(NumericUtil.hexToBytes(xpub.substring(2, 130)));*/
    }

    public String displayAddress(String path) {

        String address = null;

        try {

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
                ethapi.Eth.EthAddressRes response = ethapi.Eth.EthAddressRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                address = response.getAddress();
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");
                LogUtil.d("address：" + address);
                LogUtil.d("××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××");

            }

        } catch (Exception e) {
            LogUtil.d("异常：" + e.getMessage());
            e.printStackTrace();
        }
        return address;
        /*
        // path校验
        Path.checkPath(path);

        String mainAddr = getAddress(path);
        String apduCoinReg = Apdu.ethCoinReg(Wallet.checkedEthAddress(mainAddr).getBytes());
        String res = sendApdu(apduCoinReg);
        Apdu.checkResponse(res);
        return mainAddr;*/
    }

    public String signPersonalMessage(String path, String message, String sender) {
//        // path校验
//        Path.checkPath(path);
//
//        selectApplet();
//        byte[] dataBytes = dataToBytes(message);
//        int msgLen = dataBytes.length;
//        String headerMsg = String.format(Locale.ENGLISH, "\u0019Ethereum Signed Message:\n%d", msgLen);
//        byte[] headerMsgBytes = headerMsg.getBytes(Charset.forName("UTF-8"));
//        byte[] dataToSign = ByteUtil.concat(headerMsgBytes, dataBytes);
//
//        //byte[] dataToSignWtl = ByteUtil.concat(new byte[]{(byte)0x01}, ByteUtil.concat(new byte[]{(byte)dataToSign.length},dataToSign));
//        byte[] dataToSignWtl = ByteUtil.concat(new byte[]{(byte)0x01},
//                ByteUtil.concat(new byte[]{(byte)((dataToSign.length & 0xFF00) >> 8),(byte)(dataToSign.length & 0x00FF)}, dataToSign));
//
//
//        byte[] hashData  = Sha256Hash.hashTwice(dataToSignWtl);
//        byte[] signature = Wallet.signPackage(Sha256Hash.wrap(hashData));
//        byte[] signatureWtl = ByteUtil.concat(new byte[]{(byte)0x00}, ByteUtil.concat(new byte[]{(byte)signature.length},signature));
//        byte[] apduPack = ByteUtil.concat(signatureWtl, dataToSignWtl);
//
//        // 获取公钥
//        String getXpubApdu = Apdu.ethXpub(path, false);
//        String res = sendApdu(getXpubApdu);
//        Apdu.checkResponse(res);
//
//        String getPubKeyRes = res.substring(0, res.length() - 4);
//        String mainAddr = Wallet.publicKeyToAddress(NumericUtil.hexToBytes(getPubKeyRes.substring(2, 130)));
//        byte[] checkedAddr  = Wallet.checkedEthAddress(mainAddr).getBytes();
//
//        if (Arrays.equals(checkedAddr, sender.getBytes())) {
//            List<String> apdus = Apdu.ethMsgPrepare(ByteUtil.byteArrayToHexString(apduPack));
//            for (int i = 0; i < apdus.size(); i++) {
//                res = Ble.getInstance().sendApdu(apdus.get(i), Constants.SEND_SIGN_PRE_APDU_TIMEOUT);
//                Apdu.checkResponse(res);
//            }
//
//            String signApdu = Apdu.ethMsgSign(path);
//            String signRes = sendApdu(signApdu);
//            Apdu.checkResponse(signRes);
//
//            String r = signRes.substring(2, 66);
//            String s = signRes.substring(66, 130);
//
//
//            ECKey ecKey = ECKey.fromPublicOnly(NumericUtil.hexToBytes(getPubKeyRes.substring(0, 130)));
//
//            ECKey.ECDSASignature sig = new ECKey.ECDSASignature(new BigInteger(r, 16), new BigInteger(s, 16)).toCanonicalised();
//            String messageHash = Hash.keccak256(ByteUtil.byteArrayToHexString(dataToSign));
//            int recId = -1;
//
//            for (int i = 0; i < 4; i++) {
//                ECKey recoverKey = ECKey.recoverFromSignature(i, sig, Sha256Hash.wrap(messageHash), false);
//                if (recoverKey != null && recoverKey.getPubKeyPoint().equals(ecKey.getPubKeyPoint())) {
//                    recId = i;
//                    break;
//                }
//            }
//            if (recId == -1) {
//                throw new RuntimeException(
//                        "Could not construct a recoverable key. This should never happen.");
//            }
//
//            int headerByte = recId + 27;
//            // 1 header + 32 bytes for R + 32 bytes for S
//            byte v = (byte) headerByte;
//            byte[] rByte = NumericUtil.bigIntegerToBytesWithZeroPadded(sig.r, 32);
//            byte[] sByte = NumericUtil.bigIntegerToBytesWithZeroPadded(sig.s, 32);
//
//            return new SignatureData(v, rByte, sByte).toString();
//        } else {
//            throw new ImkeyException(Messages.IMKEY_ADDRESS_MISMATCH_WITH_PATH);
//        }
        return "";
    }

    protected String getAid() {
        return Applet.ETH_AID;
    }

    private static byte[] dataToBytes(String data) {
        byte[] messageBytes;
        if (NumericUtil.isValidHex(data)) {
            messageBytes = NumericUtil.hexToBytes(data);
        } else {
            messageBytes = data.getBytes(Charset.forName("UTF-8"));
        }
        return messageBytes;
    }
}
