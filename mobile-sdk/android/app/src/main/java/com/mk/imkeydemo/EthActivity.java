package com.mk.imkeydemo;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import com.mk.imkeydemo.core.wallet.transaction.ImKeyETHTransactionTest;
import com.mk.imkeylibrary.common.Path;
import com.mk.imkeylibrary.common.TransactionSignedResult;
import com.mk.imkeylibrary.keycore.EthApi;

import ethapi.Eth;

public class EthActivity extends AppCompatActivity {
    private ExecutorService es = ImKeyApp.es;
    TextView tvSignResult;
    private Context mContext;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_eth);

        tvSignResult = findViewById(R.id.tv_sign_result);
        mContext = this;

    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_tx_sign_auto:
                ethTxSignAutoTest();
                break;
            case R.id.btn_tx_sign:
                ethTxSignTest();
                break;
            case R.id.btn_msg_sign:
                ethMsgSignTest();
                break;
            case R.id.btn_address:
                ethAddress();
                break;
            default:
                break;
        }
    }

    private void ethTxSignAutoTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Map<String, Object> resultMap = ImKeyETHTransactionTest.testEthTxSign(mContext);

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

    private void ethTxSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Eth.EthTxRes result = ImKeyETHTransactionTest.testEthTxSign();
                    showResult(result.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void ethMsgSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    String result = ImKeyETHTransactionTest.testEthMsgSign();
                    showResult(result);
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void ethAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    String address = EthApi.displayAddress(Path.ETH_LEDGER);
                    EthApi.getAddress(Path.ETH_LEDGER);
                    showResult(address);
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
            }
        });
    }
}
