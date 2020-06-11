package test;

import cpabe.LSSSCPABE;
import cpabe.access.AccessControlEngine;
import cpabe.access.LSSSPolicyEngine;
import cpabe.utils.ParserUtils;
import cpabe.utils.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Utf8String;
import org.web3j.crypto.CipherException;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * @program: lsss
 * @description: lsss和区块链的测试类
 * @author: YST
 * @create: 2020-06-08
 **/
public class TestALL {
    private AccessControlEngine accessControlEngine;

   /* @Test
    public void test() {
        String m = "[-84, -19, 0, 5, 115, 114, 0, 41, 99, 112, 97, 98, 101, 46, 115, 101, 114, 112, 97, 114, 97, 109, 115, 46, 76, 83, 83, 83, 80, 117, 98, 108, 105, 99, 75, 101, 121, 83, 101, 114, 80, 97, 114, 97, 109, 101, 116, 101, 114, -125, 36, -44, -8, -116, 12, 92, 31, 2, 0, 5, 91, 0, 10, 98, 121, 116, 101, 65, 114, 114, 97, 121, 66, 116, 0, 2, 91, 66, 91, 0, 17, 98, 121, 116, 101, 65, 114, 114, 97, 121, 69, 103, 103, 65, 108, 112, 104, 97, 113, 0, 126, 0, 1, 91, 0, 10, 98, 121, 116, 101, 65, 114, 114, 97, 121, 70, 113, 0, 126, 0, 1, 91, 0, 10, 98, 121, 116, 101, 65, 114, 114, 97, 121, 71, 113, 0, 126, 0, 1, 91, 0, 10, 98, 121, 116, 101, 65, 114, 114, 97, 121, 72, 113, 0, 126, 0, 1, 120, 114, 0, 34, 99, 112, 97, 98, 101, 46, 117, 116, 105, 108, 115, 46, 80, 97, 105, 114, 105, 110, 103, 75, 101, 121, 83, 101, 114, 80, 97, 114, 97, 109, 101, 116, 101, 114, 126, 12, 89, 43, 56, -48, 48, 120, 2, 0, 1, 90, 0, 10, 112, 114, 105, 118, 97, 116, 101, 75, 101, 121, 120, 114, 0, 37, 99, 112, 97, 98, 101, 46, 117, 116, 105, 108, 115, 46, 80, 97, 105, 114, 105, 110, 103, 67, 105, 112, 104, 101, 114, 83, 101, 114, 80, 97, 114, 97, 109, 101, 116, 101, 114, -79, 44, 84, 54, 77, 64, -118, 90, 2, 0, 1, 76, 0, 10, 112, 97, 114, 97, 109, 101, 116, 101, 114, 115, 116, 0, 41, 76, 105, 116, 47, 117, 110, 105, 115, 97, 47, 100, 105, 97, 47, 103, 97, 115, 47, 106, 112, 98, 99, 47, 80, 97, 105, 114, 105, 110, 103, 80, 97, 114, 97, 109, 101, 116, 101, 114, 115, 59, 120, 112, 115, 114, 0, 66, 105, 116, 46, 117, 110, 105, 115, 97, 46, 100, 105, 97, 46, 103, 97, 115, 46, 112, 108, 97, 102, 46, 106, 112, 98, 99, 46, 112, 97, 105, 114, 105, 110, 103, 46, 112, 97, 114, 97, 109, 101, 116, 101, 114, 115, 46, 80, 114, 111, 112, 101, 114, 116, 105, 101, 115, 80, 97, 114, 97, 109, 101, 116, 101, 114, 115, -48, 18, 0, 3, -7, 91, -110, 18, 12, 0, 0, 120, 112, 119, -50, 0, -52, 116, 121, 112, 101, 32, 97, 10, 113, 32, 56, 49, 56, 54, 57, 57, 56, 49, 52, 49, 52, 52, 56, 54, 53, 54, 53, 56, 49, 55, 48, 52, 50, 57, 56, 55, 54, 50, 48, 48, 48, 57, 52, 50, 53, 57, 49, 54, 55, 49, 49, 49, 51, 55, 50, 52, 56, 48, 57, 52, 50, 55, 50, 51, 52, 50, 49, 51, 50, 50, 51, 56, 55, 54, 51, 54, 56, 55, 51, 48, 54, 51, 50, 56, 53, 53, 57, 10, 114, 32, 54, 48, 52, 52, 54, 50, 57, 48, 57, 56, 55, 55, 54, 56, 51, 51, 51, 49, 53, 51, 48, 55, 53, 49, 10, 104, 32, 49, 51, 53, 52, 52, 50, 53, 50, 50, 55, 51, 54, 53, 49, 50, 51, 57, 50, 52, 49, 48, 48, 53, 52, 56, 57, 50, 55, 56, 51, 57, 49, 50, 49, 52, 48, 54, 53, 53, 56, 52, 54, 54, 51, 48, 51, 50, 56, 49, 48, 56, 53, 54, 48, 10, 101, 120, 112, 49, 32, 52, 54, 10, 101, 120, 112, 50, 32, 55, 57, 10, 115, 105, 103, 110, 48, 32, 45, 49, 10, 115, 105, 103, 110, 49, 32, 49, 10, 120, 0, 117, 114, 0, 2, 91, 66, -84, -13, 23, -8, 6, 8, 84, -32, 2, 0, 0, 120, 112, 0, 0, 0, 10, 89, -78, 125, 89, -101, 108, -57, -1, -35, 112, 117, 113, 0, 126, 0, 8, 0, 0, 0, 64, 30, 27, 34, -67, 31, 112, -66, 127, 49, 26, -115, 86, 13, 124, 1, -73, -91, -100, -69, -63, -55, -29, -31, 120, -64, 81, -128, 126, 86, -4, 110, -83, 39, 70, 72, -99, 40, -77, -67, -64, -12, 114, 63, -38, -83, 35, -87, -117, -121, -78, -26, 82, -48, -29, -118, -128, 124, -12, -15, 112, 121, 116, -113, -64, 117, 113, 0, 126, 0, 8, 0, 0, 0, 64, -93, -103, 76, 49, -72, -60, 117, 4, -44, -51, 98, 4, 66, 70, -63, -126, -70, 3, 6, 20, -127, 51, 42, -25, 121, 122, -125, 16, 60, -2, 43, 98, -121, -55, 26, 111, -70, -110, -126, 102, -59, -58, 108, -73, 7, 64, 96, -103, -63, -49, -106, 93, -7, -43, 27, 117, -24, -38, 12, -31, 99, -22, 26, -80, 117, 113, 0, 126, 0, 8, 0, 0, 0, 64, -107, -83, 97, -46, -94, -13, -50, -64, -9, -3, 0, 29, -23, -23, 117, -107, -15, 106, -64, -94, -58, -25, -17, 18, -22, 127, 119, 103, -44, 46, 73, -72, -84, 1, -125, 101, -95, -84, 13, 4, -65, 112, -113, -30, 7, 104, 83, -99, -11, 66, -14, -16, -2, -22, 0, 75, -89, -77, -57, -97, 12, -93, 18, -89, 117, 113, 0, 126, 0, 8, 0, 0, 0, 64, 90, -116, -70, -17, 40, 14, -9, -106, -103, -109, 3, -44, 116, -6, 121, 65, 3, 119, 72, 87, 115, 113, -113, 108, 89, -11, 117, -3, -7, 106, 124, -27, 15, 118, 26, 111, -99, -22, -80, 124, 72, -28, 3, -21, 29, 93, 95, -24, -105, -96, -80, 108, -40, -96, -121, -22, -100, 116, 102, -70, -3, 69, 41, -85]";
        System.out.println(m.getBytes());
        HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();
        huffmanImpl1.conver2StringToByte(m);
          *//*for (int i = 0; i < m.getBytes().length; i++) {
            System.out.println(m.getBytes()[i]);
        }*//*
    }*/
/*
    @Test
    public void testEncodeString() {
        HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();
        EncodeResult result = huffmanImpl1.encode("QmVh1g359Sb2YNmEG1x2RpBpaktWGVLQMwtgYBx1BCDFGS");
        System.out.println(result.getEncode());
    }

    @Test
    public void testDecode() {
        HuffmanAlgorithmImpl1 huffmanImpl1 = new HuffmanAlgorithmImpl1();
        EncodeResult result = huffmanImpl1.encode("QmVh1g359Sb2YNmEG1x2RpBpaktWGVLQMwtgYBx1BCDFGS");
        String decode = huffmanImpl1.decode(result);
        System.out.println(decode);
    }*/

    public static void main(String[] args) throws PolicySyntaxException, IOException, CipherException {

        //设置唯一的引擎对象
        LSSSCPABE engine = LSSSCPABE.getInstance();
        engine.setAccessControlEngine(LSSSPolicyEngine.getInstance());
        //设置加密参数
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);
        Pairing pairing = PairingFactory.getPairing(pairingParameters);
        //设置web3j，以太坊的连接地址
        Web3j web3j = Web3j.build(new HttpService("http://localhost:8545"));

        /*-----------------------DO操作------------------------------------*/
        System.out.println(" /*-----------------------DO操作------------------------------------*/");
        String password = Constants.DO_PASSWORD;
        String path = Constants.DO_PATH;
        DOOperator doOperator = new DOOperator(engine, pairing, web3j, password, path);

        //1.随机生成256位的密钥对
        System.out.println("    DO生成密钥对并且生成ck");
        doOperator.generateK1K2();
        //2.发布元数据集 参数位转化的设置的属性集以及相应的版本
        //AccessPolicyExamples.access_policy_attribute, AccessPolicyExamples.v
        Scanner scanner1 = new Scanner(System.in);
        String attribute = null;
        List<Utf8String> access_policy_attribute = new ArrayList<>();
        System.out.println("    DO请输入设置的属性集合，每个属性之间用空格分离：");
        if (scanner1.hasNext()) {
            attribute = scanner1.nextLine();
        }
        System.out.println("    DO输入的属性集合为：" + attribute);
        assert attribute != null;
        String[] attributes = attribute.split(" ");
        access_policy_attribute.add(new Utf8String(" "));
        for (String s : attributes) {
            Utf8String v = new Utf8String(s.trim());
            access_policy_attribute.add(v);
        }

        String setv = null;//用户设置的版本号
        Utf8String access_policy_v = null;
        Scanner scanner2 = new Scanner(System.in);
        System.out.println("    DO请输入设置的版本号：");
        if (scanner2.hasNext()) {
            setv = scanner2.nextLine();
            if (setv != null) {
                access_policy_v = new Utf8String(setv.trim());
            }
        }
        System.out.println("    DO输入的版本号为：" + setv);
        if (access_policy_v != null) {
            System.out.println("发布元数据开始-----------------------------");
            DynamicArray<Utf8String> attri = new DynamicArray(Utf8String.class, access_policy_attribute);
            doOperator.pubData(attri, access_policy_v);//发布原生的属性集以及版本号
        } else {
            System.out.println("输入版本号有错误");
            System.exit(0);
        }

        String accessPolicyString = null;
        Scanner scanner3 = new Scanner(System.in);
        System.out.println("    请输入属性的访问策略：");//例如 "60 and 0 and 1 and (2 or 3)";
        if (scanner3.hasNext()) {
            accessPolicyString = scanner3.nextLine();
        }
        System.out.println("    输入的访问策略为：" + accessPolicyString);

        //生成属性集
        int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);//包含v attributes中无需包含v但是最后要加上去
        String[] rhos = ParserUtils.GenerateRhos(accessPolicyString); //包含v 使用另一种方式产生rhos


        //设置循环操作，并且编译为响应的jar可执行文件
        /*-----------------------DU操作------------------------------------*/
        System.out.println("/*-----------------------DU操作------------------------------------*/");
        String v = null;//Du的版本号
        Scanner scanner4 = new Scanner(System.in);
        System.out.println("    DU输入版本号：");//例如 "60 and 0 and 1 and (2 or 3)";
        if (scanner4.hasNext()) {
            v = scanner4.nextLine();
            v = v.trim();
        }
        System.out.println("    DU输入的版本号为：" + v);

        String attr = null;
        Scanner scanner5 = new Scanner(System.in);
        System.out.println("    DU输入属性集合(用空格分离)：");//例如 "60 and 0 and 1 and (2 or 3)";
        if (scanner5.hasNext()) {
            attr = scanner5.nextLine();//new String[]{"0", "1", "2"};
        }
        System.out.println("    DU输入的属性集合为：" + attr);
        assert attr != null;
        String[] attrs = attr.split(" ");

        DUOperator duOperator = new DUOperator(engine, web3j, Constants.DU1_PASSWORD, Constants.DU1_PATH, attrs, v);

        String[] newattribute = new String[60];
        int count = 0;
        boolean test = false;
        for (String att : attrs) {
            for (String rho : rhos) {
                if (att.trim().equals(rho.split("-")[0])) {
                    newattribute[count] = rho;
                    test = true;
                    count++;
                }
            }
            if (!test) {
                newattribute[count] = att;
                count++;
            }
        }
        for (String rho : rhos) {
            assert v != null;
            if (v.equals(rho.split("-")[0])) {
                v = rho;
            }
            if (setv.equals(rho.split("-")[0])) {
                setv = rho;
            }
        }
        //Arrays.copyOf(newattribute, count)
        //Arrays.copyOf(newattribute, count)

        System.out.println("/*-----------------------AC操作------------------------------------*/");
        /*-----------------------AC操作------------------------------------*/
        //3.生成访问策略，执行CP-ABE初始化算法2 生成公钥PK和系统主密钥MSK。
        ACOperator acOperator = new ACOperator(engine, web3j, Constants.AC_PASSWORD, Constants.AC_PATH, pairingParameters, Arrays.copyOf(newattribute, count), v, setv);
        System.out.println("    AC生成PK和MSK开始----------");
        acOperator.setup();
        //4.将PK存储到以太坊的的智能合约中。
        System.out.println("    AC将PK存储到以太坊的的智能合约中。");
        acOperator.setPKtoEthereum();



        /* -----------------------DO操作------------------------------------*/
        System.out.println("  /* -----------------------DO操作------------------------------------*/");
        //5.6.7. DO选择上传的文件M使用密钥ck利用对称加密机制（AES，3DES）等加密文件M，生成密文Eck(M)。将加密后的文件上传到ipfs存储网络。
        System.out.println("    DO用ck加密文件");
        doOperator.aesData();
        //8.获取公钥PK
        System.out.println("    DO从智能合约中获取系统的公钥PK");
        doOperator.getPK();
        //9.生成密文CT
        System.out.println("    DO生成密文CT");
        doOperator.generateCT(accessPolicy, rhos, setv);
        //10.11.将CT存储在ipfs网络中。
        System.out.println("    DO将CT的ipfs的地址存储在ipfs网络中。");
        doOperator.saveCTtoIPFS();
        //12.将智能合约的地址以及hashid打包上传到ipfs网络中
        System.out.println("    将智能合约的地址以及hashid打包上传到ipfs网络中");
        String packHashID = doOperator.packAll();//将文件打包到ipfs区块链网络得到的文件的打包后的ID。
        System.out.println("得到智能合约的地址是" + packHashID);


        /*-----------------------DU操作------------------------------------*/
        System.out.println("    /*-----------------------DU操作------------------------------------*/");
        System.out.println("    DU检查文件是否在区块链中");
        //14.15.DU检查文件的哈希ID，并且获得加密后的文件ECKM
        duOperator.checkHashId(packHashID);
        System.out.println("    DU检查自己的属性是否满足");
        //13.DU查看自己的属性是否满足
        boolean ifcansearch = duOperator.checkAttribute();
        if (!ifcansearch) {
            System.out.println("    属性不满足");
            System.exit(0);
        }
        System.out.println("    DU在智能合约中加入自己的属性集合");
        //16.DU设置自己的属性集
        duOperator.askAttribute();

        /*-----------------------AC操作------------------------------------*/
        System.out.println(" /*-----------------------AC操作------------------------------------*/");
        //17.将用户的属性字段和区块链已经存储的属性字段进行比较。参数是DU的地址
        System.out.println("    AC将用户的属性字段和区块链已经存储的属性字段进行比较");
        boolean compare = acOperator.compareAttribute(Constants.DU1_PATH.split("--")[2]);
        if (!compare) {
            System.exit(0);
        }
        System.out.println("    AC根据用户生成密钥SK");
        //18.生成SK。
        acOperator.keygen();
        System.out.println("    AC将SK‘存储到以太坊区块链中");
        //19 将SK‘存储到以太坊区块链中
        acOperator.putSKtoIpfs(Constants.DU1_PATH.split("--")[2]);


        /*-----------------------DO操作------------------------------------*/
        System.out.println("/*-----------------------DO操作------------------------------------*/");
        //20.DO添加有效期限
        System.out.println("    DO添加的有效期限是：" + "2020-06-13 24:00:00");
        doOperator.setInterval(Constants.DU1_PATH.split("--")[2], "2020-06-13 24:00:00");

        /*-----------------------DU操作------------------------------------*/

        System.out.println("/*-----------------------DU操作------------------------------------*/");
        //21.DU获取有效期限
        System.out.println("    DU获取有效期限：");
        boolean time = duOperator.getInterval();
        if (!time) {
            System.out.println("访问时间已经过期");
            System.exit(0);
        }
        System.out.println("    DU开始进行解密------------------------------------------------");
        //21.22. DU进行密钥的解密
        String addr = null;
        String name = null;
        Scanner scanner6 = new Scanner(System.in);
        System.out.println("DU输入要输入的文件内容的地址：");//例如 "60 and 0 and 1 and (2 or 3)";
        if (scanner6.hasNext()) {
            addr = scanner6.nextLine();//new String[]{"0", "1", "2"};
        }
        System.out.println("DU输入要输入的文件内容的地址为：" + addr);

        System.out.println("DU输入要输入的文件的名字是：");//例如 "60 and 0 and 1 and (2 or 3)";
        Scanner scanner7 = new Scanner(System.in);
        if (scanner7.hasNext()) {
            name = scanner7.nextLine();//new String[]{"0", "1", "2"};
        }
        System.out.println("DU输入的文件的名字为：" + name);

        duOperator.descryptData(accessPolicy, rhos, addr, name);

       /* scanner1.close();
        scanner2.close();
        scanner3.close();
        scanner4.close();
        scanner5.close();
        scanner6.close();
        scanner7.close();*/
    }
}
