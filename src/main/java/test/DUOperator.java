package test;

import cpabe.LSSSCPABE;
import cpabe.utils.PairingCipherSerParameter;
import cpabe.utils.PairingKeySerParameter;
import ethereum.StorageLSSS_sol_StorageLSSS;
import hellman.EncodeResult;
import hellman.HuffmanAlgorithmImpl1;
import ipfs.IpfsFile;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.abi.datatypes.generated.Bytes32;
import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.*;

/**
 * @program: lsss
 * @description: DU的操作
 * @author: YST
 * @create: 2020-06-08
 **/
public class DUOperator {
    private final LSSSCPABE engine;
    private final Web3j web3j;
    private final Credentials credentials;
    // private final String address = Constants.ADDRESS;//智能合约的地址
    private StorageLSSS_sol_StorageLSSS lsss;
    private final String[] attributes;//DU的属性集合
    private final String v;//DU的版本号
    private String file;//加密后的file的值
    private String HashEncode;//文件哈希的ID的值

    private Bytes32 hash;


    //attributes 是不添加随机数的attributes
    public DUOperator(LSSSCPABE engine, Web3j web3j, String password, String path, String[] newattributes, String v) throws IOException, CipherException { //智能有一个engine ，全局一个
        credentials = WalletUtils.loadCredentials(password, path);    //(Constants.DU1_PASSWORD, Constants.DU1_PATH);
        this.engine = engine;
        this.web3j = web3j;
        //给属性赋值
        this.attributes = newattributes;
        this.v = v;
    }

    //DU 检查属性是否满足   根据版本号
    public boolean checkAttribute() {
        Utf8String myv = new Utf8String(v);
        System.out.println("DU输入的设置的版本号为" + myv);
        List<Utf8String> setattributes = null;
        try {
            setattributes = lsss.searchData(myv).send().getValue();
            System.out.println("DU得到的以太坊中的属性合集是：" + setattributes);
            boolean temp = false;
            for (String attribute : attributes) {
                for (Utf8String setattribute : setattributes) {
                    String att = setattribute.getValue();
                    if (att.trim().equals(attribute.trim())) {
                        temp = true;
                        break;
                    }
                }
                if (!temp) {
                    System.out.println("属性集合不符合或者版本号过期请检查");
                    return false;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    //检查文件的hashid是否在区块链中
    public void checkHashId(String packHashID) {
        if (packHashID != null) {
            String result = null;
            try {
                result = new String(IpfsFile.get(packHashID));
                String address = result.split(" ")[0].split(":")[1].trim();//智能合约的地址
                HashEncode = result.split(" ")[1].split(":")[1].trim();//得到的就是文件的hash  就是hash32的类型 是哈夫曼编码得到的
                HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();

                //得到编码的文本
                Map<Character, String> letterCode = DOOperator.letterCode;

                EncodeResult result2 = new EncodeResult(HashEncode, letterCode);//Qm......

                //将二进制字符串转化为字节数组
                byte[] b = huffmanImpl1.conver2HexToByte(HashEncode);

                if (b != null) {
                    //存储到智能合约中
                    byte[] hash32 = new byte[32];
                    // System.arraycopy(hashID.getBytes(), 0, hash32, 0, hashID.length());
                    System.arraycopy(b, 0, hash32, 0, b.length);
                    //以太坊网络存储的是hash
                    hash = new Bytes32(hash32);
                }
                System.out.println("DU从ipfs上得到的智能合约的地址是:" + address + "文件的哈希为" + Arrays.toString(b));
                lsss = StorageLSSS_sol_StorageLSSS.load(address, web3j, credentials, Constants.GAS_PRICE, Constants.GAS_LIMIT);
                boolean temp = lsss.checkHash_FileId(hash).send().getValue();//智能check get不了文件的id

                if (letterCode != null) {
                    if (temp) {
                        //得到加密的文件
                        file = new String(IpfsFile.get(huffmanImpl1.decode(result2)));
                        System.out.println("DU从Ipfs网络得到文件的ECKM是:" + file);
                    }
                } else {
                    System.out.println("哈夫曼解码失败");
                    System.exit(0);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

        }
    }

    //将自己的数据集存储在区块链网络上  设置的是自己原生的属性以及版本号
    public void askAttribute() {
        List<Utf8String> newatt = new ArrayList<Utf8String>();
        if (attributes != null) {
            for (String attribute : attributes) {
                newatt.add(new Utf8String(attribute));
            }
        }
        Utf8String myv = new Utf8String(v);
        System.out.println("DU加入的属性版本是" + v + "DU加入的属性集合是" + Arrays.toString(attributes));
        DynamicArray<Utf8String> attri = new DynamicArray(Utf8String.class, newatt);
        lsss.serializationData(attri, myv);
    }

    //得到自己的有效期
    public boolean getInterval() {
        String time = null;
        try {
            time = lsss.getInterval().send().getValue();
            long time1 = Long.parseUnsignedLong(time, 16);//getTime的时间戳
            Date date = new Date();
            long time2 = date.getTime() / 1000;
            return time1 > time2;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    //解密文件   addr 是要放置的文件的位置  name 是文件的名字
    public void descryptData(int[][] accessPolicy, String[] rhos, String addr, String name) {
        byte[] byteArrayCiphertext;//密文
        byte[] byteArrayPublicKey;//PK
        byte[] byteArraySecretKey;//SKpie
        String ct = null;
        try {
            ct = lsss.getCipherText(hash).send().getValue();//得到CT文件的IPFS的路径
            //byteArraySecretKey
            String skp = lsss.getSecretKey().send().getValue();
            String tt = new String(IpfsFile.get(skp));//字符串是哈希ID

            HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();
            //  System.out.println("tt:" + tt);
            byteArraySecretKey = huffmanImpl1.conver2StringToByte(tt);//得到cipher


            String ct1 = new String(IpfsFile.get(ct));
            byteArrayCiphertext = huffmanImpl1.conver2StringToByte(ct1);
            System.out.println("DU得到输出的密文是" + Arrays.toString(byteArrayCiphertext));


            //将skpie变成sk
            Cipher cipher = Cipher.getInstance("AES");// 创建密码器
            SecretKeySpec key = new SecretKeySpec(ACOperator.skKey, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化为加密模式的密码器
            byte[] skpie = cipher.doFinal(byteArraySecretKey);// 解密 生成了SK
            System.out.println("DU得到SK是" + Arrays.toString(skpie));

            String pkk = lsss.getPK().send().getValue();
            byteArrayPublicKey = huffmanImpl1.conver2StringToByte(pkk);
            System.out.println("DU得到PK是" + Arrays.toString(byteArrayPublicKey));

            CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
            PairingKeySerParameter publicKey = (PairingKeySerParameter) anPublicKey;
            CipherParameters anSecretKey = TestUtils.deserCipherParameters(skpie);
            PairingKeySerParameter secretKey = (PairingKeySerParameter) anSecretKey;
            CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
            PairingCipherSerParameter ciphertext = (PairingCipherSerParameter) anCiphertext;

            Element k1 = engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
            byte[] k1_ = k1.getImmutable().toBytes();
            byte[] k2 = DOOperator.k2;
            byte[] ck = new byte[32];
            for (int i = 0; i < ck.length; i++) {
                ck[i] = (byte) (k1_[i] ^ k2[i]);
            }
            System.out.print("DU通过运算得到ck为：" + Arrays.toString(ck));//ck得到的是对的

            Cipher cipher1 = Cipher.getInstance("AES");// 创建密码器
            SecretKeySpec key1 = new SecretKeySpec(ck, "AES");
            cipher1.init(Cipher.DECRYPT_MODE, key1);// 初始化为解密模式的密码器

            byte[] file_ = cipher1.doFinal(huffmanImpl1.conver2StringToByte(file));// 解密
            InputStream in = new ByteArrayInputStream(file_);
            File file1 = new File(addr);
            if (file1.exists()) {
                File file2 = new File(file1.getAbsolutePath() + "/" + name);
                System.out.println(file1.getAbsolutePath() + name);
                if (!file2.exists()) {
                    file2.createNewFile();
                    OutputStream out = new FileOutputStream(file2);
                    byte[] buffer = new byte[1024 * 4];
                    int n = 0;
                    while ((n = in.read(buffer)) != -1) {
                        out.write(buffer, 0, n);
                    }
                    out.close();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
