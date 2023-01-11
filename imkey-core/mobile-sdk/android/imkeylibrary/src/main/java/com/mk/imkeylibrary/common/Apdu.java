package com.mk.imkeylibrary.common;


import com.mk.imkeylibrary.exception.ImkeyException;

public class Apdu {

    public static void checkResponse(String res) {
        if(res.endsWith(Constants.APDU_RSP_SUCCESS)) {
            return;
        }

        if(res.equals(Constants.APDU_RSP_USER_NOT_CONFIRMED)) {
            throw new ImkeyException(Messages.IMKEY_USER_NOT_CONFIRMED);
        } else if(res.equals(Constants.APDU_CONDITIONS_NOT_SATISFIED)) {
            throw new ImkeyException(Messages.IMKEY_CONDITIONS_NOT_SATISFIED);
        } else if(res.equals(Constants.APDU_RSP_INCORRECT_P1P2)) {
            throw new ImkeyException(Messages.IMKEY_COMMAND_FORMAT_ERROR);
        } else if(res.equals(Constants.APDU_RSP_CLA_NOT_SUPPORTED)) {
            throw new ImkeyException(Messages.IMKEY_COMMAND_FORMAT_ERROR);
        } else if(res.equals(Constants.APDU_RSP_APPLET_WRONG_DATA)) {
            throw new ImkeyException(Messages.IMKEY_COMMAND_DATA_ERROR);
        } else if(res.equals(Constants.APDU_RSP_APPLET_NOT_EXIST)) {
            throw new ImkeyException(Messages.IMKEY_APPLET_NOT_EXIST);
        } else if(res.equals(Constants.APDU_RSP_WRONG_LENGTH)) {
            throw new ImkeyException(Messages.IMKEY_APDU_WRONG_LENGTH);
        } else if(res.equals(Constants.APDU_RSP_SIGNATURE_VERIFY_FAILED)) {
            throw new ImkeyException(Messages.IMKEY_SIGNATURE_VERIFY_FAIL);
        } else if(res.equals(Constants.APDU_BLUETOOTH_CHANNEL_ERROR)) {
            throw new ImkeyException(Messages.IMKEY_BLUETOOTH_CHANNEL_ERROR);
        } else if(res.equals(Constants.APDU_RSP_FUNCTION_NOT_SUPPORTED)) {
            throw new ImkeyException(Messages.IMKEY_APPLET_FUNCTION_NOT_SUPPORTED);
        } else if(res.equals(Constants.APDU_RSP_EXCEEDED_MAX_UTXO_NUMBER)) {
            throw new ImkeyException(Messages.IMKEY_EXCEEDED_MAX_UTXO_NUMBER);
        } else {
            throw new ImkeyException(Messages.IMKEY_COMMAND_EXECUTE_FAIL + "_" + res);
        }

    }

    public static void checkImKeyStatus(String res) {

        if(res.equals(Constants.APDU_RSP_WALLET_NOT_CREATED)){
            throw new ImkeyException(Messages.IMKEY_WALLET_NOT_CREATED);
        }
        if(res.equals(Constants.APDU_RSP_IN_MENU_PAGE)){
            throw new ImkeyException(Messages.IMKEY_IN_MENU_PAGE);
        }
        if(res.equals(Constants.APDU_RSP_PIN_NOT_VERIFIED)){
            throw new ImkeyException(Messages.IMKEY_PIN_NOT_VERIFIED);
        }
    }
}
