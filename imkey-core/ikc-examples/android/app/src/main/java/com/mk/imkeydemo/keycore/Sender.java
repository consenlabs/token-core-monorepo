package com.mk.imkeydemo.keycore;

import com.sun.jna.Callback;

public interface Sender extends Callback{
    String sendApdu(String apdu, int timeout);
}
