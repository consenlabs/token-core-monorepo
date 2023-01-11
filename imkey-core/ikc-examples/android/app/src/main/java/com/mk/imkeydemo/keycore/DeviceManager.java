package com.mk.imkeydemo.keycore;

import android.content.Context;

import com.google.protobuf.Any;
import com.mk.imkeydemo.utils.NumericUtil;

import java.util.regex.Pattern;

import deviceapi.Device;
import im.imkey.imkeylibrary.utils.ByteUtil;
import im.imkey.imkeylibrary.utils.LogUtil;

public class DeviceManager {

    /**
     * get se id
     *
     * @return
     */
    public String getSeId() {
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_seid")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String seid = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetSeidRes response = Device.GetSeidRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            seid = response.getSeid();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return seid;

    }

    public String getSn() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_sn")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String sn = null;
        try {
            String sn_result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetSnRes response = Device.GetSnRes.parseFrom(ByteUtil.hexStringToByteArray(sn_result));
            sn = response.getSn();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return sn;
    }

    public int getRamSize() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_ram_size")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetRamSizeRes response = Device.GetRamSizeRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getRamSize();
        } catch (Exception e) {
            e.printStackTrace();
        }

        String hexSize = res.substring(4,8);
        return Integer.parseInt(hexSize,16);
    }

    /**
     * 获取固件版本
     * @return
     */
    public String getFirmwareVersion() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_firmware_version")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        String version = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetFirmwareVersionRes response = Device.GetFirmwareVersionRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getFirmwareVersion();
        } catch (Exception e) {
            e.printStackTrace();
        }

        StringBuffer sb = new StringBuffer();
        sb.append(res.substring(0, 1));
        sb.append('.');
        sb.append(res.substring(1, 2));
        sb.append('.');
        sb.append(res.substring(2));
        return sb.toString();
    }

    /**
     * get device remaining battery power
     *
     * @return
     */
    public String getBatteryPower() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_battery_power")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetBatteryPowerRes response = Device.GetBatteryPowerRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getBatteryPower();
        } catch (Exception e) {
            e.printStackTrace();
        }


        String batteryPower = res;
        if (!batteryPower.equals(Constants.BATTERY_CHARGING_SIGN)) {
            batteryPower = String.valueOf(Integer.parseInt(batteryPower, 16));
        }

        return batteryPower;
    }

    /**
     * 获取硬件当前生命周期
     * @return
     */
    public String getLifeTime() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_life_time")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetLifeTimeRes response = Device.GetLifeTimeRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getLifeTime();
        } catch (Exception e) {
            e.printStackTrace();
        }

        /*String res = Ble.getInstance().sendApdu(Constants.APDU_GET_LIFE_TIME);
        Apdu.checkResponse(res);*/
        //String lifeTime = Apdu.getResponseData(res);
        switch (res) {
            case "80":
                return Constants.LIFE_TIME_DEVICE_INITED;
            case "89":
                return Constants.LIFE_TIME_DEVICE_ACTIVATED;
            case "81":
                return Constants.LIFE_TIME_UNSET_PIN;
            case "83":
                return Constants.LIFE_TIME_WALLET_UNREADY;
            case "84":
                return Constants.LIFE_TIME_WALLET_CREATTING;
            case "85":
                return Constants.LIFE_TIME_WALLET_RECOVERING;
            case "86":
                return Constants.LIFE_TIME_WALLET_READY;
            default:
                return Constants.LIFE_TIME_UNKNOWN;
        }
    }

    public String getBleName() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_ble_name")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetBleNameRes response = Device.GetBleNameRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getBleName();
        } catch (Exception e) {
            e.printStackTrace();
        }

        //String result = Ble.getInstance().sendApdu(Constants.APDU_GET_BLE_NAME);

        byte[] bytes = ByteUtil.hexStringToByteArray(res);
        res = new String(bytes);
        return res;
    }

    public void setBleName(String bleName) {

        String regEx = "^[a-zA-Z0-9\\-]{1,12}$";
//        if(!Pattern.matches(regEx, bleName)) {
//            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
//        }

//        String apdu = Apdu.setBleName(bleName);
//        String result = Ble.getInstance().sendApdu(apdu);

        deviceapi.Device.SetBleNameReq req = deviceapi.Device.SetBleNameReq.newBuilder()
                .setBleName(bleName)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("set_ble_name")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            //Device.SeQueryResponse response = Device.SeQueryResponse.parseFrom(ByteUtil.hexStringToByteArray(result));
            //String s = response.toString();
            LogUtil.d(result);
        } catch (Exception e) {
            e.printStackTrace();
        }


        /*String apdu = Apdu.setBleName(bleName);
        String result = Ble.getInstance().sendApdu(apdu);
        Apdu.checkResponse(result);*/
    }

    /**
     * 获取蓝牙版本
     * @return
     */
    public String getBleVersion() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_ble_version")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetBleVersionRes response = Device.GetBleVersionRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getBleVersion();
        } catch (Exception e) {
            e.printStackTrace();
        }


        /*Ble.getInstance().sendApdu(Constants.APDU_SELECT_ISD);
        String result = Ble.getInstance().sendApdu(Constants.APDU_GET_BLE_VERSION);
        Apdu.checkResponse(result);*/
        String version = res.substring(0, 4);
        String[] chas = version.split("");
        return chas[1] + "." + chas[2] + "." + chas[3] + chas[4];
    }

//    private String getCert() {
//        Ble.getInstance().sendApdu(Constants.APDU_SELECT_ISD);
//        return Ble.getInstance().sendApdu(Constants.APDU_GET_CERT);
//    }

    public void checkDevice() {


        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("device_secure_check")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            //Device.SeQueryResponse response = Device.SeQueryResponse.parseFrom(ByteUtil.hexStringToByteArray(result));
            //String s = response.toString();
            LogUtil.d(result);
        } catch (Exception e) {
            e.printStackTrace();
        }

        /*String seId = getSeId();
        String sn = getSn();

        // 组织请求参数
        SeSecureCheckRequest request = new SeSecureCheckRequest();
        request.setStepKey("01");
        request.setSeid(seId);
        request.setSn(sn);
        request.setDeviceCert(getCert());
        List<String> list = new ArrayList<>();
        request.setCardRetDataList(list);

        SeSecureCheckResponse response = Constantsnew SeCheck().checkSe(request);

        // 判断处理状态
        String returnCode = response.get_ReturnCode();
        if (!Constants.TSM_RETURNCODE_SUCCESS.equals(returnCode)) {
            if (Constants.TSM_RETURNCODE_DEVICE_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_AUTHENTICITY_CHECK_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEV_INACTIVATED.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_NOT_ACTIVATED);
            } else if (Constants.TSM_RETURNCODE_DEVICE_ILLEGAL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ILLEGAL);
            } else if (Constants.TSM_RETURNCODE_OCE_CERT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_OCE_CERT_CHECK_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_STOP_USING.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_STOP_USING);
            } else if (Constants.TSM_RETURNCODE_RECEIPT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_RECEIPT_CHECK_FAIL);
            } else {
                throw new ImkeyException(Messages.IMKEY_TSM_SERVER_ERROR + "_" + returnCode);
            }
        }*/
    }


    public void activeDevice() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("device_activate")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            //Device.SeQueryResponse response = Device.SeQueryResponse.parseFrom(ByteUtil.hexStringToByteArray(result));
            //String s = response.toString();
            LogUtil.d(result);
        } catch (Exception e) {
            e.printStackTrace();
        }

        /*
        String seId = getSeId();
        String sn = getSn();

        SeActivateRequest request = new SeActivateRequest();
        request.setStepKey("01");
        request.setSeid(seId);
        request.setSn(sn);
        request.setStatusWord("");
        request.setDeviceCert(getCert());
        List<String> list = new ArrayList<>();
        request.setCardRetDataList(list);

        SeActivateResponse response = new SeActive().activeSe(request);

        // 判断处理状态
        String returnCode = response.get_ReturnCode();
        if (!Constants.TSM_RETURNCODE_SUCCESS.equals(returnCode)) {
            if (Constants.TSM_RETURNCODE_DEVICE_ACTIVE_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ACTIVE_FAIL);
            } else if (Constants.TSM_RETURNCODE_SEID_ILLEGAL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ILLEGAL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_STOP_USING.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_STOP_USING);
            } else {
                throw new ImkeyException(Messages.IMKEY_TSM_SERVER_ERROR + "_" + returnCode);
            }
        }*/

    }

    public String checkUpdate() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("check_update")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        Device.CheckUpdateRes response = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            response = Device.CheckUpdateRes.parseFrom(ByteUtil.hexStringToByteArray(result));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response.toString();

        /*ImKeyDevice imKeyDevice = new ImKeyDevice();
        String seId = getSeId();
        String sn = getSn();

        imKeyDevice.setSeid(seId);
        imKeyDevice.setSn(sn);

        SeQuery seQuery = new SeQuery();
        SeInfoQueryRequest request = new SeInfoQueryRequest();
        request.setStepKey("01");
        request.setSeid(seId);
        request.setSn(sn);
        request.setSdkVersion(Constants.version);

        SeInfoQueryResponse response = seQuery.query(request);

        String returnCode = response.get_ReturnCode();
        if (Constants.TSM_RETURNCODE_SUCCESS.equals(returnCode)) {
            imKeyDevice.setStatus(Constants.IMKEY_DEV_STATUS_LATEST);
            imKeyDevice.setSdkMode(response.getSdkMode());
            imKeyDevice.setAvailableAppList(response.getAvailableAppList());

        } else if (Constants.TSM_RETURNCODE_DEV_INACTIVATED.equals(returnCode)) {
            imKeyDevice.setStatus(Constants.IMKEY_DEV_STATUS_INACTIVATED);
            imKeyDevice.setSdkMode(response.getSdkMode());
            imKeyDevice.setAvailableAppList(response.getAvailableAppList());

        } else if (Constants.TSM_RETURNCODE_DEVICE_ILLEGAL.equals(returnCode)) {
            throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ILLEGAL);
        } else if (Constants.TSM_RETURNCODE_DEVICE_STOP_USING.equals(returnCode)) {
            throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_STOP_USING);
        } else if (Constants.TSM_RETURNCODE_SE_QUERY_FAIL.equals(returnCode)) {
            throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_UPDATE_CHECK_FAIL);
        } else {
            throw new ImkeyException(Messages.IMKEY_TSM_SERVER_ERROR + "_" + returnCode);
        }
        return imKeyDevice;*/
    }

    public void download(String appletName) {


        deviceapi.Device.AppDownloadReq req = deviceapi.Device.AppDownloadReq.newBuilder()
                .setAppName(appletName)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_download")
                .setParam(any)
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            //Device.SeQueryResponse response = Device.SeQueryResponse.parseFrom(ByteUtil.hexStringToByteArray(result));
            //String s = response.toString();
            LogUtil.d(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        /*
        String seId = getSeId();

        AppDownloadRequest request = new AppDownloadRequest();
        request.setStepKey("01");
        request.setSeid(seId);
        request.setInstanceAid(Applet.appletName2instanceAid(appletName));
        request.setDeviceCert(getCert());
        request.setStatusWord("");
        List<String> list = new ArrayList<>();
        request.setCardRetDataList(list);

        AppDownloadResponse response = new AppDownload().download(request);

        String returnCode = response.get_ReturnCode();
        if (!Constants.TSM_RETURNCODE_SUCCESS.equals(returnCode)) {
            if (Constants.TSM_RETURNCODE_APP_DOWNLOAD_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_APP_DOWNLOAD_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_ILLEGAL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ILLEGAL);
            } else if (Constants.TSM_RETURNCODE_OCE_CERT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_OCE_CERT_CHECK_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_STOP_USING.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_STOP_USING);
            } else if (Constants.TSM_RETURNCODE_RECEIPT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_RECEIPT_CHECK_FAIL);
            } else {
                throw new ImkeyException(Messages.IMKEY_TSM_SERVER_ERROR + "_" + returnCode);
            }
        }*/

    }

    public void update(String appletName) {

        deviceapi.Device.AppUpdateReq req = deviceapi.Device.AppUpdateReq.newBuilder()
                .setAppName(appletName)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_update")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            //Device.SeQueryResponse response = Device.SeQueryResponse.parseFrom(ByteUtil.hexStringToByteArray(result));
            //String s = response.toString();
            LogUtil.d(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        /*
        String seId = getSeId();

        AppUpdateRequest request = new AppUpdateRequest();
        request.setStepKey("01");
        request.setSeid(seId);
        request.setInstanceAid(Applet.appletName2instanceAid(appletName));
        request.setDeviceCert(getCert());
        request.setStatusWord("");
        List<String> list = new ArrayList<>();
        request.setCardRetDataList(list);

        AppUpdateResponse response = new AppUpdate().update(request);

        String returnCode = response.get_ReturnCode();
        if (!Constants.TSM_RETURNCODE_SUCCESS.equals(returnCode)) {
            if (Constants.TSM_RETURNCODE_APP_UPDATE_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_APP_UPDATE_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_ILLEGAL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ILLEGAL);
            } else if (Constants.TSM_RETURNCODE_OCE_CERT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_OCE_CERT_CHECK_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_STOP_USING.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_STOP_USING);
            } else if (Constants.TSM_RETURNCODE_RECEIPT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_RECEIPT_CHECK_FAIL);
            } else {
                throw new ImkeyException(Messages.IMKEY_TSM_SERVER_ERROR + "_" + returnCode);
            }
        }*/

    }

    public void delete(String appletName) {

        deviceapi.Device.AppDeleteReq req = deviceapi.Device.AppDeleteReq.newBuilder()
                .setAppName(appletName)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();


        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("app_delete")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            //Device.SeQueryResponse response = Device.SeQueryResponse.parseFrom(ByteUtil.hexStringToByteArray(result));
            //String s = response.toString();
            LogUtil.d(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        /*
        String seId = getSeId();

        AppDeleteRequest request = new AppDeleteRequest();
        request.setStepKey("01");
        request.setSeid(seId);
        request.setInstanceAid(Applet.appletName2instanceAid(appletName));
        request.setDeviceCert(getCert());
        request.setStatusWord("");
        List<String> list = new ArrayList<>();
        request.setCardRetDataList(list);

        AppDeleteResponse response = new AppDelete().delete(request);

        String returnCode = response.get_ReturnCode();
        if (!Constants.TSM_RETURNCODE_SUCCESS.equals(returnCode)) {
            if (Constants.TSM_RETURNCODE_APP_DELETE_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_APP_DELETE_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_ILLEGAL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_ILLEGAL);
            } else if (Constants.TSM_RETURNCODE_OCE_CERT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_OCE_CERT_CHECK_FAIL);
            } else if (Constants.TSM_RETURNCODE_DEVICE_STOP_USING.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_DEVICE_STOP_USING);
            } else if (Constants.TSM_RETURNCODE_RECEIPT_CHECK_FAIL.equals(returnCode)) {
                throw new ImkeyException(Messages.IMKEY_TSM_RECEIPT_CHECK_FAIL);
            } else {
                throw new ImkeyException(Messages.IMKEY_TSM_SERVER_ERROR + "_" + returnCode);
            }
        }*/

    }

    /**
     * 设备绑定状态核查
     * @return
     */
    public String bindCheck(Context context) {

//        Context context = Ble.getInstance().getContext();
//        if(null == context) {
//            throw new ImkeyException(Messages.IMKEY_SDK_BLE_NOT_INITIALIZE);
//        }

        // file名称与seid关联，支持一个手机，绑定多个设备
        String  filePath = context.getFilesDir().getPath();

        deviceapi.Device.BindCheckReq req = deviceapi.Device.BindCheckReq.newBuilder()
                .setFilePath(filePath)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_check")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        String status = null;
        try {
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
                Device.BindCheckRes response = Device.BindCheckRes.parseFrom(ByteUtil.hexStringToByteArray(result));
                status = response.getBindStatus();
                LogUtil.d("绑定状态：" + status);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return  status;
    }

    /**
         * 显示绑定码
     * @return
     */
    public void displayBindingCode() {
        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_display")
                .build();

        String hex = NumericUtil.bytesToHex(action.toByteArray());

        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
        } catch (Exception e) {
            e.printStackTrace();
        }

        //  产生随机绑定码
        /*String generateAuthCodeApdu = Apdu.generateAuthCode();
        String res = Ble.getInstance().sendApdu(generateAuthCodeApdu);
        Apdu.checkResponse(res);*/
    }


    public String bindAcquire(String bindingCode) {

        deviceapi.Device.BindAcquireReq req = deviceapi.Device.BindAcquireReq.newBuilder()
                .setBindCode(bindingCode)
                .build();

        Any any = Any.newBuilder()
                .setValue(req.toByteString())
                .build();

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("bind_acquire")
                .setParam(any)
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());
        String status = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.BindAcquireRes response = Device.BindAcquireRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            status = response.getBindResult();
            status = Constants.identityVerifyStatusMap.get(status);
            LogUtil.d("绑定状态：" + status);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return  status;
        /*


        bindingCode = bindingCode.toUpperCase();
        // authCode 校验  0,1,I,O,排除
        String regEx = "^[A-HJ-NP-Z2-9]{8}$";
        if(!Pattern.matches(regEx, bindingCode)) {
            throw new ImkeyException(Messages.IMKEY_SDK_ILLEGAL_ARGUMENT);
        }
        // 保存authCode，先存储再验证
        String authCodeCipher = null;
        try {
            authCodeCipher = ByteUtil.byteArrayToHexString(RsaCrypto.encryptByPublicKeyWithPadding(bindingCode.getBytes(), Base64.decode(Constants.AUTHCODE_ENC_PUB_KEY, Base64.DEFAULT)));
        } catch(Exception e) {
            throw new ImkeyException(Messages.IMKEY_ENCRYPT_AUTHCODE_FAIL);
        }
        authCodeStorage(authCodeCipher);

        // select applet
        selectApplet();
        byte[] data = new byte[8 + 65 + 65]; // 授权码、apppk、sepk
        System.arraycopy(bindingCode.getBytes(), 0, data, 0, 8);
        System.arraycopy(KeyManager.getInstance().getPubKey(), 0, data, 8, 65);
        System.arraycopy(KeyManager.getInstance().getSePubKey(), 0, data, 73, 65);
        //计算hash
        byte[] hash = Hash.sha256(data);
        //加密hash
        byte[] cipher = AES.encryptByCBC(hash, KeyManager.getInstance().getSessionKey(), genIV(bindingCode));

        data = new byte[KeyManager.getInstance().getPubKey().length + cipher.length];
        System.arraycopy(KeyManager.getInstance().getPubKey(), 0, data, 0, KeyManager.getInstance().getPubKey().length);
        System.arraycopy(cipher, 0, data, KeyManager.getInstance().getPubKey().length, cipher.length);

        String identityVerifyApdu = Apdu.identityVerify((byte)0x80, data);
        String res = Ble.getInstance().sendApdu(identityVerifyApdu);
        Apdu.checkResponse(res);

        String status = res.substring(0,2);*/
        // 返回状态
        //return Constants.identityVerifyStatusMap.get(status);
    }



    public SdkInfo getSdkInfo() {

        api.Api.ImkeyAction action = api.Api.ImkeyAction.newBuilder()
                .setMethod("get_sdk_info")
                .build();
        String hex = NumericUtil.bytesToHex(action.toByteArray());

        String res = null;
        try {
            String result = RustApi.INSTANCE.call_imkey_api(hex);
            Device.GetSdkInfoRes response = Device.GetSdkInfoRes.parseFrom(ByteUtil.hexStringToByteArray(result));
            res = response.getSdkVersion();
        } catch (Exception e) {
            e.printStackTrace();
        }

        SdkInfo sdkInfo = new SdkInfo();
        sdkInfo.setSdkVersion(res);
        return sdkInfo;
    }

}
