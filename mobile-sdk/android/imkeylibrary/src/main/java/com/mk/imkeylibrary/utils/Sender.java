package com.mk.imkeylibrary.utils;

import com.sun.jna.Callback;

public interface Sender extends Callback{
    String sendApdu(String apdu, int timeout);
}
