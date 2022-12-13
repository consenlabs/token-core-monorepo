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

import com.mk.imkeydemo.core.wallet.transaction.ImKeyBitcoinTransactionTest;
import com.mk.imkeydemo.core.wallet.transaction.ImKeyOmniTransactionTest;
import com.mk.imkeylibrary.common.TransactionSignedResult;
import com.mk.imkeylibrary.keycore.BtcApi;

public class BtcActivity extends AppCompatActivity {
    private ExecutorService es = ImKeyApp.es;
    TextView tvSignResult;
    private Context mContext;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_btc);

        tvSignResult = findViewById(R.id.tv_sign_result);
        mContext = this;

    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_tx_sign_auto:
                btcTxSignAutoTest();
                break;
            case R.id.btn_segwit_tx_sign_auto:
                btcSegwitTxSignAutoTest();
                break;
            case R.id.btn_usdt_tx_sign_auto:
                usdtTxSignAutoTest();
                break;
            case R.id.btn_usdt_segwit_tx_sign_auto:
                usdtSegwitTxSignAutoTest();
                break;
            case R.id.btn_tx_sign:
                btcTxSignTest();
                break;
            case R.id.btn_segwit_tx_sign:
                btcSegwitTxSignTest();
                break;
            case R.id.btn_usdt_tx_sign:
                usdtTxSignTest();
                break;
            case R.id.btn_usdt_segwit_tx_sign:
                usdtSegwitTxSignTest();
                break;
            case R.id.btn_address:
                btcAddress();
                break;
            case R.id.btn_segwit_address:
                btcSegwitAddress();
                break;
            case R.id.btn_reg_address:
                btcRegAddress();
                break;
            case R.id.btn_reg_segwit_address:
                btcRegSegwitAddress();
                break;
            default:
                break;
        }
    }

    private void btcTxSignAutoTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    Map<String, Object> resultMap = ImKeyBitcoinTransactionTest.testBitcoinSign(mContext);

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

    private void btcSegwitTxSignAutoTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                Map<String, Object> resultMap = ImKeyBitcoinTransactionTest.testBitcoinSegwitSign(mContext);

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

    private void usdtTxSignAutoTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                Map<String, Object> resultMap = ImKeyOmniTransactionTest.testUxdtTxSign(mContext);

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

    private void usdtSegwitTxSignAutoTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                Map<String, Object> resultMap = ImKeyOmniTransactionTest.testUsdtSegwitTxSign(mContext);

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

    private void btcTxSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    TransactionSignedResult result = ImKeyBitcoinTransactionTest.testBitcoinSign();
                    showResult(result.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void btcSegwitTxSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    TransactionSignedResult result = ImKeyBitcoinTransactionTest.testBitcoinSegwitSign();
                    showResult(result.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void usdtTxSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    TransactionSignedResult result = ImKeyOmniTransactionTest.testUxdtTxSign();
                    showResult(result.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void usdtSegwitTxSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    TransactionSignedResult result = ImKeyOmniTransactionTest.testUsdtSegwitTxSign();
                    showResult(result.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }

    private void btcAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                String address = BtcApi.getAddress(BtcApi.NETWORK_MAINNET,"m/44'/0'/0'/0/0");
                showResult(address.toString());
            } catch (Exception e) {
                showResult(e.getMessage());
            }
            }
        });
    }

    private void btcSegwitAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                String address = BtcApi.getSegWitAddress(BtcApi.NETWORK_MAINNET, "m/49'/0'/0'/0/22");
                showResult(address);
            } catch (Exception e) {
                showResult(e.getMessage());
            }
            }
        });
    }

    private void btcRegAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                String address = BtcApi.displayAddress(BtcApi.NETWORK_MAINNET, "m/44'/0'/0'/0/0");
                showResult(address);
            } catch (Exception e) {
                showResult(e.getMessage());
            }
            }
        });
    }

    private void btcRegSegwitAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                String address = BtcApi.displaySegWitAddress(BtcApi.NETWORK_MAINNET, "m/49'/0'/0'/0/0");
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
