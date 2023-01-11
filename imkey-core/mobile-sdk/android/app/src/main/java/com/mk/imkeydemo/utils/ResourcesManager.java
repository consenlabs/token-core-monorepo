package com.mk.imkeydemo.utils;

import android.content.Context;

import org.json.JSONObject;

import java.io.InputStream;
import java.lang.reflect.Field;

public class ResourcesManager {

  public static JSONObject getFromRaw(Context context, String rawid){
    JSONObject jsonObject = null;
    try {

      Class c = Class.forName("com.mk.imkeydemo.R$raw");
      Object obj = c.newInstance();
      Field field = c.getField(rawid);
      InputStream in = context.getResources().openRawResource((int)field.get(obj));
      int lenght = in.available();
      byte[] buffer = new byte[lenght];
      in.read(buffer);
      jsonObject = new JSONObject(new String(buffer, "utf-8"));

    } catch (Exception e) {
      e.printStackTrace();
    }
    return jsonObject;
  }


}
