package com.mk.imkeylibrary.keycore;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import java.nio.charset.StandardCharsets;

/** Host-owned callback storage. Rust serializes callbacks through response copying. */
final class CallbackResponseBuffer {
    private static final int CAPACITY = 131089; // Maximum ISO APDU hex response plus NUL.
    private final Memory memory = new Memory(CAPACITY);

    synchronized Pointer store(String response) {
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        if (bytes.length >= CAPACITY) {
            bytes = "communication_error_imkey_transport_illegal_response".getBytes(StandardCharsets.UTF_8);
        }
        memory.write(0, bytes, 0, bytes.length);
        memory.setByte(bytes.length, (byte) 0);
        return memory;
    }
}
