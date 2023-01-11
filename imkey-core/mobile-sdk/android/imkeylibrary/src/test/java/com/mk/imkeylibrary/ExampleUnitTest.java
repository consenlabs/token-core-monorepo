package com.mk.imkeylibrary;

import com.mk.imkeylibrary.net.Https;
import com.mk.imkeylibrary.utils.NumericUtil;

import org.bitcoinj.core.Address;
import org.bitcoinj.core.ECKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
    public void test_pubKeyCompression(){
            String pubkey = "04F028892BAD7ED57D2FB57BF33081D5CFCF6F9ED3D3D7F159C2E2FFF579DC341A07CF33DA18BD734C600B96A72BBC4749D5141C90EC8AC328AE52DDFE2E505BDB";
            ECKey key = getECKeyFromCompress(NumericUtil.hexToBytes(pubkey));
        Address test = Address.fromBase58(null,"1Q5YjKVj5yQWHBBsyEBamkfph3cA6G9KK8");
            assertNotNull(key);
    }

    private ECKey getECKeyFromCompress(byte[] pubKeyUncompress) {
        //@XM@20180723 now is manually TODO: find our the ECkey compress method
        byte[] desPubKey = new byte[33];
        System.arraycopy(pubKeyUncompress, 33, desPubKey, 1, 32);
        if ((desPubKey[32] % 2) != 0) desPubKey[0] = 0x03;
        else desPubKey[0] = 0x02;

        System.arraycopy(pubKeyUncompress, 1, desPubKey, 1, 32);
        return (ECKey.fromPublicOnly(desPubKey));

        //ECKey key = ECKey.fromPublicOnly(pubKeyUncompressed);
    }

    @Test
    public void test_htttps() {
       String res =  Https.post("appDelete", "123");
       System.out.print(res);
    }
}