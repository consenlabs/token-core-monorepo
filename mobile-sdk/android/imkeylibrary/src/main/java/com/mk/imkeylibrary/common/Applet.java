package com.mk.imkeylibrary.common;

public class Applet {
    public static final String BTC_NAME = "BTC";
    public static final String ETH_NAME = "ETH";
    public static final String EOS_NAME = "EOS";
    public static final String IMK_NAME = "IMK";
    public static final String COSMOS_NAME = "COSMOS";
    public static final String BTC_AID = "695F627463";
    public static final String ETH_AID = "695F657468";
    public static final String EOS_AID = "695F656F73";
    public static final String IMK_AID = "695F696D6B";
    public static final String COSMOS_AID = "695F636F736D6F73";

    public static String instanceAid2AppletName(String aid) {
        switch (aid) {
            case BTC_AID:
                return BTC_NAME;
            case ETH_AID:
                return ETH_NAME;
            case EOS_AID:
                return EOS_NAME;
            case IMK_AID:
                return IMK_NAME;
            case COSMOS_AID:
                return COSMOS_NAME;
        }
        return "";
    }

    public static String appletName2instanceAid(String appletName) {
        switch (appletName) {
            case BTC_NAME:
                return BTC_AID;
            case ETH_NAME:
                return ETH_AID;
            case EOS_NAME:
                return EOS_AID;
            case IMK_NAME:
                return IMK_AID;
            case COSMOS_NAME:
                return COSMOS_AID;
        }
        return "";
    }
}
