package com.mk.imkeylibrary;


import com.mk.imkeylibrary.utils.ByteUtil;

import org.junit.Assert;
import org.junit.Test;


public class ByteUtilTest {
    @Test
    public void testHexStringToByteArray() {
        byte[] bytes = ByteUtil.hexStringToByteArray("00A40400");
        byte[] result = {0,-92,4,0};
        Assert.assertArrayEquals(result, bytes);
    }

    @Test
    public void testByteArrayToHexString() {
        byte[] bytes = {0,-92,4,0};
        String result = ByteUtil.byteArrayToHexString(bytes);
        Assert.assertEquals("00A40400", result);
    }

    @Test
    public void testLongToByteArray() {
        byte[] bytes = ByteUtil.longToByteArray(127);
        byte[] result = {0,0,0,0,0,0,0,127};
        Assert.assertArrayEquals(result, bytes);
    }

    @Test
    public void testConcat(){
        byte[] bytes1 = {0,1};
        byte[] bytes2 = {3,4};
        byte[] bytes3 = ByteUtil.concat(bytes1,bytes2);
        byte[] result = {0,1,3,4};
        Assert.assertArrayEquals(result, bytes3);
    }
}
