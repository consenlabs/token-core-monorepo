package com.mk.imkeydemo;

import android.content.Context;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;

import com.mk.imkeydemo.core.wallet.transaction.ImKeyEosTransactionTest;
import com.mk.imkeydemo.core.wallet.transaction.ImKeyFilecoinTransactionTest;
import com.mk.imkeydemo.keycore.Eos;
import com.mk.imkeydemo.keycore.Filecoin;
import com.mk.imkeydemo.keycore.Path;
import com.mk.imkeydemo.keycore.TransactionSignedResult;
import com.mk.imkeydemo.keycore.TxMultiSignResult;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;

import im.imkey.imkeylibrary.utils.LogUtil;


public class FilecoinActivity extends AppCompatActivity {
    private ExecutorService es = ImKeyApp.es;
    TextView tvSignResult;
    private Context mContext;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_filecoin);

        tvSignResult = findViewById(R.id.tv_sign_result);
        mContext = this;

    }

    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.btn_tx_sign:
                txSignTest();
                break;
            case R.id.btn_address:
                getAddress();
                break;
            case R.id.btn_display_address:
                displayAddress();
                break;
            default:
                break;
        }
    }

    private void txSignTest(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    TransactionSignedResult signResult = ImKeyFilecoinTransactionTest.testFilecoinTxSign();
                    showResult(signResult.toString());
                } catch (Exception e) {
                    showResult(e.getMessage());
                }
            }
        });
    }


    private void getAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
            try {
                String address = new Filecoin().getAddress(Path.FILECOIN_LEDGER);
                showResult(address);
            } catch (Exception e) {
                showResult(e.getMessage());
            }

            }
        });
    }

    private void displayAddress(){
        es.execute(new Runnable() {
            @Override
            public void run() {
                try {
                    String address = new Filecoin().displayAddress(Path.FILECOIN_LEDGER);
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
                LogUtil.d(msg);
            }
        });
    }
}
