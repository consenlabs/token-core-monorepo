package com.mk.imkeylibrary;


import com.mk.imkeylibrary.core.Apdu;
import com.mk.imkeylibrary.core.wallet.Path;
import com.mk.imkeylibrary.device.Applet;

import org.junit.Assert;
import org.junit.Test;

import java.util.List;

public class ApduTest {


    @Test
    public void testSelectBtc() {
        String apdu = Apdu.select(Applet.BTC_AID);
        Assert.assertEquals("00A404000F62616F64616F746F6E673031303030", apdu);
    }

    @Test
    public void testBtcPrepare() {
        String data = "01000000047a222fb053b6e5339a9b6f9649f88a9481606cf3c64c4557802b3a819ddf3a98000000001976a914a189f2f7836812aa7a0e36e28a20a10e64010bf688acffffffff31b5a9794dcaf82af1738745afe1ecf402ea4a93e71ae75c7d3d8bf7c78aef45010000001976a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788acffffffffa92c40dfd195a188d87110557fb7f46dbbfb68c4bb8718f33dc31d61927ec614000000001976a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788acffffffffb99a3e8884b14f330d2a444a4bc2a03af16804fb99b5e37ee892ed5db8b67f11010000001976a91415c4698fadd6a54dede98c2fbc62fb21b13b0d7788acffffffff028017b42c000000001976a91455bdc1b42e3bed851959846ddf600e96125423e088ac0e47f302000000001976a914b501bc45363560f6d7ad066733e4b393a324befb88ac0000000001000000000000000007A9720000";
        List<String> apdus = Apdu.btcPrepare(data);
        String lastApdu = "804180806F698FADD6A54DEDE98C2FBC62FB21B13B0D7788ACFFFFFFFF028017B42C000000001976A91455BDC1B42E3BED851959846DDF600E96125423E088AC0E47F302000000001976A914B501BC45363560F6D7AD066733E4B393A324BEFB88AC0000000001000000000000000007A972000000";
        Assert.assertEquals(lastApdu,apdus.get(apdus.size()-1));
    }

    @Test
    public void testBtcSign() {
        String path = "m/44'/0'/0'/0/22";
        String apdu = Apdu.btcSign(0,Apdu.Hash_ALL,path);
        Assert.assertEquals("80420001106D2F3434272F30272F30272F302F323200",apdu);
    }

    @Test
    public void testBtcSegwitPrepare() {
        String data = "0200000001df368297e7031809cadcec02a7f96cf05bf2e6495a1f39266634f973548d56cd010000001976a914eff7556e9e3ed0ac0ae9648f79aa51cd38f79b8088acffffffff8fcd7000000000000240420f00000000001976a91413a33f6bf97ac355f005a042a9eb5e9fc19930f588acb4f65e000000000017a914be62a91a162a92d03936ae99c0d71a7777b3fbeb870000000001000000000000000002949Bc46f";
        List<String> apdus = Apdu.btcSegwitPrepare(data);
        String lastApdu = "80310080A40200000001DF368297E7031809CADCEC02A7F96CF05BF2E6495A1F39266634F973548D56CD010000001976A914EFF7556E9E3ED0AC0AE9648F79AA51CD38F79B8088ACFFFFFFFF8FCD7000000000000240420F00000000001976A91413A33F6BF97AC355F005A042A9EB5E9FC19930F588ACB4F65E000000000017A914BE62A91A162A92D03936AE99C0D71A7777B3FBEB870000000001000000000000000002949BC46F00";
        Assert.assertEquals(lastApdu,apdus.get(apdus.size()-1));
    }

    @Test
    public void testBtcSegwitSign() {
//        String path = "m/49'/1'/0'/1/6";
//        String apdu = Apdu.btcSegwitSign(0,Apdu.Hash_ALL,path);
//        Assert.assertEquals("803200010F6D2F3439272F31272F30272F312F3600",apdu);
    }

    @Test
    public void testEthMsgPrepare() {
        String data = "19457468657265756D205369676E6564204D6573736167653A0A313348656C6C6F20696D546F6B656E";
        List<String> apdus = Apdu.ethMsgPrepare(data);

        String lastApdu = "805400802919457468657265756D205369676E6564204D6573736167653A0A313348656C6C6F20696D546F6B656E00";
        Assert.assertEquals(lastApdu,apdus.get(apdus.size()-1));
    }

    @Test
    public void testEthMsgSign() {
        String path = "m/44'/60'/0'/0/0";
        String apdu = Apdu.ethMsgSign(path);
        Assert.assertEquals("80550000106D2F3434272F3630272F30272F302F3000",apdu);
    }

    @Test
    public void testEosPrepare() {
        String data = "0004085c97bd0704786d746f0806786d66726f6d0907322e30303030300a064c584d454f530120b998c88d8478e87e6dee727adecec067a3201da03ec8f8e8861c946559be635505116d2f3434272f313934272f30272f302f30";
        List<String> apdus = Apdu.eosPrepare(data);
        String lastApdu = "806100805A0004085C97BD0704786D746F0806786D66726F6D0907322E30303030300A064C584D454F530120B998C88D8478E87E6DEE727ADECEC067A3201DA03EC8F8E8861C946559BE635505116D2F3434272F313934272F30272F302F3000";
        Assert.assertEquals(lastApdu,apdus.get(apdus.size()-1));
    }

    @Test
    public void testEosTxSign() {
        String apdu = Apdu.eosTxSign(22);
        Assert.assertEquals("8062000002001600",apdu);
    }

    @Test
    public void testBtcXpub() {
        String apdu = Apdu.btcXpub(Path.BTC_PATH_PREFIX,true);
        Assert.assertEquals("804300000C6D2F3434272F30272F30272F00",apdu);
    }

    @Test
    public void testEthXpub() {
        String path = "m/44'/60'/0'/0/0";
        String apdu = Apdu.ethXpub(path,true);
        Assert.assertEquals("80530000106D2F3434272F3630272F30272F302F3000",apdu);
    }

    @Test
    public void testEospub() {
        String apdu = Apdu.eosPub(Path.EOS_LEDGER,true);
        Assert.assertEquals("80630000116D2F3434272F313934272F30272F302F3000",apdu);
    }

    @Test
    public void testSetBleName() {
        String name = "oooo";
        String apdu = Apdu.setBleName(name);
        Assert.assertEquals("FFDA4654046F6F6F6F00",apdu);
    }

    @Test
    public void testBech32() {
        byte[] bytes = {0x00,0x01,0x02};
        String ret = Bech32.encode("bech32",bytes);
        Assert.assertEquals("bech321qqqsyrhqy2a",ret);
    }
}
