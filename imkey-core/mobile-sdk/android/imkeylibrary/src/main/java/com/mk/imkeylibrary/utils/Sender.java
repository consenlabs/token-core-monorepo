package com.mk.imkeylibrary.utils;

import com.sun.jna.Callback;

public interface Sender extends Callback{
    // Rust borrows this host-owned response until it has copied it.
    com.sun.jna.Pointer sendApdu(String apdu, int timeout);
}
