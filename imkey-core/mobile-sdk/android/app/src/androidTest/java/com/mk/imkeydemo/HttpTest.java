package com.mk.imkeydemo;

import android.support.test.runner.AndroidJUnit4;

import org.json.JSONException;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import com.mk.imkeylibrary.net.Https;

import static org.junit.Assert.assertNotNull;


@RunWith(AndroidJUnit4.class)
public class HttpTest {
    @Test
    public void response_notnull() {
        JSONObject jsonObject = null;
        try {
            jsonObject = new JSONObject("{seid:'18000001010000000016',stepKey:'01',sn:'123456',statusWord:''}");
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if(jsonObject != null)
        {
            String res = Https.post("seActivate",jsonObject.toString());
            assertNotNull(res);
        }
    }
}
