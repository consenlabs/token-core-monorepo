package com.mk.imkeydemo;

import android.content.Context;
import android.content.SharedPreferences;

public class SpTool {
    private static final String SP_NAME = "imkey";
    private static SharedPreferences sharedPreferences;
    private static SpTool spTool = new SpTool();

    private SpTool(){
    }

    public static SpTool ins(Context context){
        sharedPreferences = context.getSharedPreferences(SP_NAME,Context.MODE_PRIVATE);
        return spTool;
    }

    public void saveBindCode(String deviceMac,String bindingCode){
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(deviceMac,bindingCode);
        editor.commit();
    }

    public String getBindCode(String deviceMac){
        return sharedPreferences.getString(deviceMac,"");
    }
}
