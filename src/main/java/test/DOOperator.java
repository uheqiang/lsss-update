package test;

import cpabe.LSSSCPABE;
import cpabe.utils.PairingCipherSerParameter;
import cpabe.utils.PairingKeySerParameter;
import ethereum.StorageLSSS_sol_StorageLSSS;
import hellman.EncodeResult;
import hellman.HuffmanAlgorithmImpl1;
import ipfs.IpfsFile;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import org.bouncycastle.crypto.CipherParameters;
import org.junit.Assert;
import org.junit.Test;
import org.web3j.abi.datatypes.Address;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.Scanner;

/**
 * @program: lsss
 * @description: DO的操作
 * @author: YST
 * @create: 2020-06-08
 **/
public class DOOperator {
    private final LSSSCPABE engine;

    private byte[] k1;
    public static byte[] k2;
    private byte[] ck;

    private PairingKeySerParameter publicKey;
    //可以将ciphertext字节流化。
    private byte[] byteArrayCipherext;
    private Bytes32 hash;//文件的哈希id的值
    private String hashEncode = null;

    private final Pairing pairing;

    byte[] result;//加密的Eck(M)
    private final StorageLSSS_sol_StorageLSSS lsss;

    //编码的文本
    public static Map<Character, String> letterCode = null;
    public static Map<Character, String> ctletterCode = null;


    public DOOperator(LSSSCPABE engine, Pairing pairing, Web3j web3j, String password, String path) throws IOException, CipherException {
        this.engine = engine;
        this.pairing = pairing;
        Credentials credentials = WalletUtils.loadCredentials(password, path);
        //智能合约的地址
        String address = Constants.ADDRESS;
        lsss = StorageLSSS_sol_StorageLSSS.load(address, web3j, credentials, Constants.GAS_PRICE, Constants.GAS_LIMIT);
    }

    //随机生成密钥对 aes算法 无种子生成
    @Test
    public void generateK1K2() {
        KeyGenerator kgen = null;
        try {
            kgen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // 利用用户密码作为随机数初始化出128位的key生产者
        //SecureRandom 是生成安全随机数序列，password.getBytes() 是种子，只要种子相同，序列就一样，密钥也一样
        assert kgen != null;
        kgen.init(256);
        // 根据用户密码，生成一个密钥
//50 -26 58 42 17 91 -2 120 -53 100 51 124 21 -6 19 54 -94 -89 59 -29 -67 71 -85 118 109 -123 -9 -72 99 -81 72 8
        SecretKey secretKey = kgen.generateKey();
        SecretKey secretKey1 = kgen.generateKey();
        ck = new byte[32];
        k1 = secretKey.getEncoded();
        k2 = secretKey1.getEncoded();
        // long k11 = Long.parseLong(Arrays.toString(k1));
        //long k22 = Long.parseLong(Arrays.toString(k2));
        for (int i = 0; i < ck.length; i++) {
            ck[i] = (byte) (k1[i] ^ k2[i]);
            System.out.print(ck[i] + " ");
        }
        // System.out.println(Arrays.toString(k1) + " " + Arrays.toString(k2) + " " + Arrays.toString(ck));
    }

    //DO 发布元数据集
    public void pubData(final DynamicArray<Utf8String> attribute, final Utf8String setv) {
        try {
            lsss.pub_data(attribute, setv).send();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private byte[] toByteArray(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024 * 4];
        int n = 0;
        while ((n = in.read(buffer)) != -1) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }


    //将文件加密之后上传 aes
    public void aesData() {
        String address = null;
        Scanner scanner = new Scanner(System.in);
        System.out.println("请DO输入要加密的文件全路径地址：");
        if (scanner.hasNext()) {
            address = scanner.next();
            System.out.println("输入的地址为：" + address);
        }
        if (address != null) {
            File file = new File(address);
            if (file.exists()) {
                InputStream in = null;
                try {
                    in = new FileInputStream(address);
                    byte[] data = toByteArray(in);
                    in.close();
                    Cipher cipher;// 创建密码器
                    cipher = Cipher.getInstance("AES");
                    SecretKeySpec key = new SecretKeySpec(ck, "AES");
                    assert cipher != null;
                    cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化为加密模式的密码器
                    result = cipher.doFinal(data);
                } catch (IOException | NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                    e.printStackTrace();
                }
                if (result != null) {
                    //上传到ipfs网络
                    try {
                        String hashID = IpfsFile.add(Arrays.toString(result).getBytes());
                        //以Qm开头有很多位。对返回的文件的id进行编码，根据hashID可以得到文件的ECKM
                        System.out.println("上传的文件的哈希ID为" + hashID);

                        HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();
                        EncodeResult result = huffmanImpl1.encode(hashID);
                        //得到编码的文本
                        letterCode = huffmanImpl1.getLetterCode(hashID);

                        hashEncode = result.getEncode();
                        //将二进制字符串转化为字节数组
                        byte[] b = huffmanImpl1.conver2HexToByte(hashEncode);

                        System.out.println("哈希ID的哈夫曼编码为" + result.getEncode());
                        if (hashID != null) {
                            //存储到智能合约中
                            byte[] hash32 = new byte[32];
                            // System.arraycopy(hashID.getBytes(), 0, hash32, 0, hashID.length());
                            System.arraycopy(b, 0, hash32, 0, b.length);
                            //以太坊网络存储的是hash
                            hash = new Bytes32(hash32);
                            lsss.setHash_FileId(hash).send();
                        } else {
                            System.out.println("文件上传ipfs失败");
                            System.exit(0);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    //得到PK
    public void getPK() {
        try {
            String PK = lsss.getPK().send().getValue();//已经是字节数组了
            //  System.out.println("DO得到的PK是" + PK);
            HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();
            CipherParameters anPublicKey = TestUtils.deserCipherParameters(huffmanImpl1.conver2StringToByte(PK));
            publicKey = (PairingKeySerParameter) anPublicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        //先执行AC在执行此函数
        // Pairing pairing = PairingFactory.getPairing(ACOperator.pairingParameters);
    }

    //生成CT 输入访问策略，通过公钥PK，密钥k1，以及访问策略lsss和版本v。
    public void generateCT(int[][] accessPolicy, String[] rhos, String setv) {
        try {//rho 是根据标志得到属性， attributes是是否符合的属性集合  在多个属性的情况下进行处理
            //Encryption and serialization
            //把k1进行加密
            Element k1_element = pairing.getGT().newElementFromBytes(k1).getImmutable();
            PairingCipherSerParameter ciphertext = engine.encryption(publicKey, accessPolicy, rhos, k1_element, setv); //用setv加密
            //可以将Ciphertext 数组流化。
            byte[] byteArrayCipher_text = TestUtils.SerCipherParameter(ciphertext);
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCipher_text);
            Assert.assertEquals(ciphertext, anCiphertext);
            byteArrayCipherext = byteArrayCipher_text;
            ciphertext = (PairingCipherSerParameter) anCiphertext;
            // //System.out.println("message=" + message);

        } catch (Exception e) {
            e.printStackTrace();
            // System.exit(1);
        }
    }

    //将CT存储到区块链网络中
    public void saveCTtoIPFS() throws IOException {
        //new LSSSCiphertextSerParameter(publicKeyParameter.getParameters(), CPrime, rhom, C, C0, C1i, C2i, C3i, C1v, C2v, C3v);

        //将ct文件存储在ipfs网络中，返回的是ct文件的路径保存在智能合约中
        String hashID = IpfsFile.add(Arrays.toString(this.byteArrayCipherext).getBytes());
        if (hashID != null) {
            //存储到智能合约中
           /* byte[] hash32 = new byte[32];
            System.arraycopy(hashID.getBytes(), 0, hash32, 0, b.length);*/
            Utf8String ct = new Utf8String(hashID);
            try {
                lsss.setCipherText(hash, ct).send();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    //将storageipfs的地址以及文件的id和EckM上传到ipfs中
    public String packAll() throws IOException {
        String all = "address:" + Constants.ADDRESS + " " + "HashId:" + hashEncode + "";
        //打包的所有的文件的id
        //存储到智能合约中
        return IpfsFile.add(all.getBytes());
    }

    //设置用户的访问期限 得到用户的地址
    //将时间戳转换为16进制的字符串
    public void setInterval(String duaddress, String time) {
        //time 是访问的日期
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = null;
        try {
            date = simpleDateFormat.parse(time);
            long ts = date.getTime() / 1000;//获取时间的时间戳
            String stap = Long.toHexString(ts);//十六进制的字符串

            Address address1 = new Address(duaddress);
            Utf8String time_utf = new Utf8String(stap);
            System.out.println("time_utf：" + time_utf.getValue());
            lsss.setInterval(address1, time_utf).send();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
