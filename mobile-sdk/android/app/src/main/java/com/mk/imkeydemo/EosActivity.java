package com.mk.imkeydemo;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import com.mk.imkeydemo.core.wallet.transaction.ImKeyEosTransactionTest;
import com.mk.imkeylibrary.common.Path;
import com.mk.imkeylibrary.common.TxMultiSignResult;
import com.mk.imkeylibrary.keycore.EosApi;
import com.mk.imkeylibrary.utils.LogUtil;

public class EosActivity extends AppCompatActivity {
    private ExecutorService es = ImKeyApp.es;
    TextView tvSignResult;
    private Context mContext;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_eos);

        tvSignResult = findViewById(R.id.tv_sign_result);
        mContext = this;

    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_tx_sign_auto:
                eosTxSignAutoTest();
                break;
            case R.id.btn_tx_sign:
                eosTxSignTest();
                break;
            case R.id.btn_msg_sign:
                eosMsgSignTest();
                break;
            case R.id.btn_public_key:
                eosPubKey();
                break;
            default:
                break;
        }
    }

    private void eosTxSignAutoTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Map<String, Object> resultMap = ImKeyEosTransactionTest.testEosTxSign(mContext);

                    int successCount = (int)resultMap.get("successCount");
                    String result = "Number of successes: " + successCount + "\n";
                    int failCount = (int)resultMap.get("failCount");
                    result = result + "Number of failures: " + failCount + "\n";
                    result = result + "Failed test case name:\n";

                    ArrayList<String> failedCaseName = (ArrayList)resultMap.get("failedCaseName");
                    for(int i=0; i<failedCaseName.size(); i++) {
                        result = result + failedCaseName.get(i) + "\n";
                    }
                    showResult(result);
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void eosTxSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    List<TxMultiSignResult> signResults = ImKeyEosTransactionTest.testEosTxSign();
                    showResult(signResults.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void eosMsgSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    String result = ImKeyEosTransactionTest.testEosMsgSign();
                    showResult(result);
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void eosPubKey(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                EosApi.getPubKey(Path.EOS_LEDGER);
                String pubKey = EosApi.displayPubKey(Path.EOS_LEDGER);
                showResult(pubKey);
            } catch (Exception e) {
                showResult(e.getMessage());
            }

            }
        });
    }

    private void showResult(final String msg) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                tvSignResult.setText(msg);
                LogUtil.d(msg);
            }
        });
    }
}
