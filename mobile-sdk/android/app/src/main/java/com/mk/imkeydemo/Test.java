package com.mk.imkeydemo;

import com.mk.imkeylibrary.utils.LogUtil;

public class Test {
    public void factCallback(int res) {
        System.out.println("factCallback: res = " + res);
        LogUtil.d("factCallback: res = " + res);
    }
}
