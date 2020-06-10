package test;

import cpabe.LSSSCPABE;
import cpabe.utils.PairingKeySerPair;
import cpabe.utils.PairingKeySerParameter;
import ethereum.StorageLSSS_sol_StorageLSSS;
import ipfs.IpfsFile;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/**
 * @program: lsss
 * @description: AC的操作
 * @author: YST
 * @create: 2020-06-08
 **/
public class ACOperator {
    private LSSSCPABE engine;
    private StorageLSSS_sol_StorageLSSS lsss;
    private byte[] byteArrayPublicKey;
    private PairingKeySerParameter publicKey;
    private PairingKeySerParameter masterKey;


    public PairingParameters pairingParameters;
    private final String address = Constants.ADDRESS;//智能合约的地址
    //DU的私钥
    private byte[] byteArraySecretKey;
    //DU的属性
    private List<Utf8String> att;
    //DO设置的版本号
    //  String setv;
    private String v;
    //Sk的加密的key
    public static byte[] skKey;

    //加随机数之后的文件的attributes
    private String[] attributes;
    private String v_random;
    private String setv_random;

    public ACOperator(LSSSCPABE engine, Web3j web3j, String password, String path, PairingParameters pairingParameters, String[] attributes, String v, String setv) throws IOException, CipherException {
        this.engine = engine;
        this.pairingParameters = pairingParameters;
        this.v_random = v;
        this.setv_random = setv;
        this.attributes = attributes;
        Credentials credentials = WalletUtils.loadCredentials(password, path);
        lsss = StorageLSSS_sol_StorageLSSS.load(address, web3j, credentials, Constants.GAS_PRICE, Constants.GAS_LIMIT);
    }

    //AC 生成PK和主密钥MSK
    public void setup() {

        //public
        PairingKeySerPair keyPair = engine.setup(pairingParameters, 50);
        publicKey = keyPair.getPublic();
        byte[] byteArrayPublic_Key = new byte[0];
        try {
            byteArrayPublic_Key = TestUtils.SerCipherParameter(publicKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
        CipherParameters anPublicKey = null;
        try {
            anPublicKey = TestUtils.deserCipherParameters(byteArrayPublic_Key);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        Assert.assertEquals(publicKey, anPublicKey);//判断类型是否匹配
        publicKey = (PairingKeySerParameter) anPublicKey;
        byteArrayPublicKey = byteArrayPublic_Key;


        //master
        masterKey = keyPair.getPrivate();
        byte[] byteArrayMasterKey = new byte[0];
        try {
            byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
        } catch (IOException e) {
            e.printStackTrace();
        }
        CipherParameters anMasterKey = null;
        try {
            anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
        Assert.assertEquals(masterKey, anMasterKey);
        masterKey = (PairingKeySerParameter) anMasterKey;

        // Pairing pairing = PairingFactory.getPairing(pairingParameters);
    }

    //将PK存储到以太坊链数据库中，调用AC的账户名
    public void setPKtoEthereum() {
        Utf8String pk = new Utf8String(Arrays.toString(this.byteArrayPublicKey));
        System.out.println("AC设置的PK是" + pk.getValue());
        try {
            lsss.setPK(pk).send();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //对比用户的属性集 输入的是用户的地址，得到用户的属性集,输入版本号
    public boolean compareAttribute(String duaddress) {
        Address address1 = new Address(duaddress);
        //用户得到属性集和版本号
        try {
            att = lsss.getData(address1).send().getValue();
            v = lsss.getV(address1).send().getValue();
            //对比用户的属性集和区块链上的属性集的区别
            //根据版本号查找区块链上的属性集
            //this.setv = setv;
            Utf8String myv = new Utf8String(v);
            List<Utf8String> setattributes = lsss.searchData(myv).send().getValue();
            boolean temp = false;
            for (Utf8String utf8String : att) {
                String att_temp = utf8String.getValue();
                for (Utf8String setattribute : setattributes) {
                    if (att_temp.equals(setattribute.getValue())) {
                        temp = true;
                        break;
                    }
                }
                if (!temp) {
                    System.out.println("属性集合不符合请检查");
                    return false;
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    //执行keyGen算法
    public void keygen() {
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, attributes, v_random, setv_random);//用v生成sk  setv为了验证版本号是否一致
        if (secretKey == null) {
            System.out.println("版本需要更新");
        }
        try {
            byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
            CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
            Assert.assertEquals(secretKey, anSecretKey);
            secretKey = (PairingKeySerParameter) anSecretKey;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    //AC 得到AC的secretkey 将其布置到ipfs中
    public void putSKtoIpfs(String duaddress) {
        byte[] Key = byteArraySecretKey;
        Address address1 = new Address(duaddress);
        //生成SK‘
        KeyGenerator kgen = null;
        try {// Utf8String pk = new Utf8String(Arrays.toString(this.byteArrayPublicKey));
            kgen = KeyGenerator.getInstance("AES");
            // 利用用户密码作为随机数初始化出128位的key生产者
            //SecureRandom 是生成安全随机数序列，password.getBytes() 是种子，只要种子相同，序列就一样，密钥也一样
            kgen.init(256);
            // 根据用户密码，生成一个密钥
            SecretKey secretKey = kgen.generateKey();
            skKey = secretKey.getEncoded();
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            SecretKeySpec key = new SecretKeySpec(skKey, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化为加密模式的密码器
            // cipher.doFinal(Key);// 加密 生成了SK’
            //将SK‘存储在ipfs的区块链上 存储的是其加密后的地址


            String hashID = IpfsFile.add(Arrays.toString(cipher.doFinal(Key)).getBytes());//skpie 在ipfs网络中
            System.out.println("AC设置的SK的ipfs的返回路径是" + hashID);
           /* for (int i = 0; i < cipher.doFinal(Key).length; i++)
                System.out.println("AC设置的SK的ipfs的返回路径是" + cipher.doFinal(Key)[i]);*/
            if (hashID != null) {
                //存储到智能合约中
           /* byte[] hash32 = new byte[32];
            System.arraycopy(hashID.getBytes(), 0, hash32, 0, b.length);*/
                Utf8String skp = new Utf8String(hashID);
                try {
                    lsss.setSecretKey(address1, skp).send();
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

//            Utf8String skpie = new Utf8String(Arrays.toString(m));   //Arrays.toString(Key));
//            System.out.println("skpie" + skpie.getValue());

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
