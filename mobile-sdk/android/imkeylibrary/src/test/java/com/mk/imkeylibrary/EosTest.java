package com.mk.imkeylibrary;


import com.mk.imkeylibrary.core.wallet.transaction.ImKeyEOSTransaction;

import android.content.Context;

import com.mk.imkeylibrary.bluetooth.BleDevice;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class EosTest {
    @Test
    public void eosSignTransactions() {
        // construct  to sign objects
        List<ImKeyEOSTransaction.ToSignObj> toSignObjs = new ArrayList<>();
        ImKeyEOSTransaction.ToSignObj toSignObj = new ImKeyEOSTransaction.ToSignObj();
        toSignObj.setPublicKeys(Collections.singletonList("EOS5SxZMjhKiXsmjxac8HBx56wWdZV1sCLZESh3ys1rzbMn4FUumU"));
        toSignObj.setTxHex("c578065b93aec6a7c811000000000100a6823403ea3055000000572d3ccdcd01000000602a48b37400000000a8ed323225000000602a48b374208410425c95b1ca80969800000000000453595300000000046d656d6f00");
        toSignObjs.add(toSignObj);
        Context mContext = null;
        BleDevice mDevice = null;
        ImKeyEOSTransaction eosTransaction = new ImKeyEOSTransaction(toSignObjs);
        String chainIdEos  = "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906";
        //String previewInfo = "0704786d746f0806786d66726f6d0906313233343536";
        String to = "786d746f";
        String from = "786d66726f6d";
        String amount = "313233343536";
        String pathEos = "m/44'/194'/0'/0/0";
//        List<TxMultiSignResult> signResults = eosTransaction.signTransactions(chainIdEos, to, from, amount, pathEos);
        //@XM now can only compare signRaw with apduPack
        String signRaw = "00044cabb9db0704786d746f0806786d66726f6d09063132333435360120b998c88d8478e87e6dee727adecec067a3201da03ec8f8e8861c946559be635505116d2f3434272f313934272f30272f302f30";

        /* only test serialization at now
        junit.framework.Assert.assertEquals(1, signResults.size());
        TxMultiSignResult actualResult = signResults.get(0);
        junit.framework.Assert.assertEquals(1, actualResult.getSigned().size());
        junit.framework.Assert.assertEquals("SIG_K1_KkCTdqnTztAPnYeB2TWhrqcDhnnLvFJJdXnFCE3g8jRyz2heCggDQt5bMABu4LawHaDy4taHwJR3XMKV2ZXnBWqyiBnQ9J", actualResult.getSigned().get(0));
        junit.framework.Assert.assertEquals("6af5b3ae9871c25e2de195168ed7423f455a68330955701e327f02276bb34088", actualResult.getTxHash());
        */
    }
}
