package im.imkey.bledemo;

import android.app.Application;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ImKeyApp extends Application{

    public static ExecutorService es = Executors.newCachedThreadPool();

    @Override
    public void onCreate() {
        super.onCreate();
    }

}
