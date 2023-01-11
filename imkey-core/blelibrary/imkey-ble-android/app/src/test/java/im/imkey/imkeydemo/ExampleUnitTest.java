package im.imkey.imkeydemo;

import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void addition_isCorrect() {
        assertEquals(4, 2 + 2);
    }

    @Test
    public void test_splitString(){
        String sig = "41AEE8624342246E0F0C3E193B1F93671B0893A89AFBFA68E4CD6600C505BAF2FCA1A26AF8587489FCF1C2FA474DBB8D528A1AAA163E40F90D4564571C9BD18E3C009000";
        String r = sig.substring(2,66);
        String s = sig.substring(66,130);
        System.out.print(r + " " + s);
    }
}