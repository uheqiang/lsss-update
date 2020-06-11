package test;

import cpabe.LSSSCPABE;
import cpabe.access.AccessControlEngine;
import cpabe.access.LSSSPolicyEngine;
import cpabe.access.UnsatisfiedAccessControlException;
import cpabe.utils.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Assert;

import java.io.IOException;
import java.util.Arrays;

/**
 * @program: lsss
 * @description: 对lsss的测试类
 * @author: YST
 * @create: 2020-05-27
 **/
//extends TestCase
public class TestLSSS extends TestCase {
    private AccessControlEngine accessControlEngine;
    private LSSSCPABE engine;

    public void runAllTests(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey) {
        //  Pairing pairing = PairingFactory.getPairing(pairingParameters);
        //test satisfied access control
        //第一个是v第二个是setv
        System.out.println("Test example 1");
        System.out.println("尝试的策略是：" + AccessPolicyExamples.access_policy_example_1 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户a：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_1_satisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1,
                AccessPolicyExamples.access_policy_example_1_satisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户b：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_1_satisfied_2) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1,
                AccessPolicyExamples.access_policy_example_1_satisfied_2, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户c：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_1_unsatisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_invalid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1,
                AccessPolicyExamples.access_policy_example_1_unsatisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);

        //test example 2
        System.out.println("Test example 2");
        System.out.println("尝试的策略是：" + AccessPolicyExamples.access_policy_example_2 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户a：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_2_satisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_example_2_satisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户b：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_2_satisfied_2) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_example_2_satisfied_2, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户c：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_2_unsatisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_invalid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_example_2_unsatisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户d：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_2_unsatisfied_2) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_invalid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_example_2_unsatisfied_2, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户e：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_2_unsatisfied_3) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_invalid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_2,
                AccessPolicyExamples.access_policy_example_2_unsatisfied_3, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);

        //test example 3
        System.out.println("Test example 3");
        System.out.println("尝试的策略是：" + AccessPolicyExamples.access_policy_example_3 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户a：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_3_satisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_example_3_satisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户b：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_3_unsatisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_invalid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_example_3_unsatisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户c：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_3_unsatisfied_2) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_invalid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_example_3_unsatisfied_2, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);

        System.out.println("尝试版本号");
        System.out.println("尝试的策略是：" + AccessPolicyExamples.access_policy_example_3 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v1);
        System.out.println("用户a：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_3_satisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v2);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_3,
                AccessPolicyExamples.access_policy_example_3_satisfied_1, AccessPolicyExamples.access_policy_example_v2, AccessPolicyExamples.access_policy_example_v1);

        System.out.println("尝试多个属性");
        System.out.println("尝试的策略是：" + AccessPolicyExamples.access_policy_example_4 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v);
        System.out.println("用户a：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_4_satisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v);
        try_valid_access_policy(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_4,
                AccessPolicyExamples.access_policy_example_4_satisfied_1, AccessPolicyExamples.access_policy_example_v, AccessPolicyExamples.access_policy_example_v);

        System.out.println("尝试策略更新");
        System.out.println("尝试的策略是：旧策略" + AccessPolicyExamples.access_policy_example_1 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v1);
        System.out.println("尝试的策略是：新策略" + AccessPolicyExamples.access_policy_example_4 + "-------" + "版本号是：" + AccessPolicyExamples.access_policy_example_v1);
        System.out.println("用户a：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_4_satisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v1);
        //更新策略1
        try_valid_access_policy1(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1, AccessPolicyExamples.access_policy_example_4,
                AccessPolicyExamples.access_policy_example_4_satisfied_1, AccessPolicyExamples.access_policy_example_v1, AccessPolicyExamples.access_policy_example_v1);
        System.out.println("用户b：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_4_satisfied_3) + "版本号" + AccessPolicyExamples.access_policy_example_v1);
        try_valid_access_policy1(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1, AccessPolicyExamples.access_policy_example_4,
                AccessPolicyExamples.access_policy_example_4_satisfied_3, AccessPolicyExamples.access_policy_example_v1, AccessPolicyExamples.access_policy_example_v1);
        System.out.println("用户c：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_4_satisfied_4) + "版本号" + AccessPolicyExamples.access_policy_example_v1);
        try_valid_access_policy1(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1, AccessPolicyExamples.access_policy_example_4,
                AccessPolicyExamples.access_policy_example_4_satisfied_4, AccessPolicyExamples.access_policy_example_v1, AccessPolicyExamples.access_policy_example_v1);
        System.out.println("用户d：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_4_satisfied_2) + "版本号" + AccessPolicyExamples.access_policy_example_v1);
        try_valid_access_policy1(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1, AccessPolicyExamples.access_policy_example_4,
                AccessPolicyExamples.access_policy_example_4_satisfied_2, AccessPolicyExamples.access_policy_example_v1, AccessPolicyExamples.access_policy_example_v1);
        System.out.println("用户e：" + "属性：" + Arrays.toString(AccessPolicyExamples.access_policy_example_4_unsatisfied_1) + "版本号" + AccessPolicyExamples.access_policy_example_v1);
        try_valid_access_policy1(
                pairing, publicKey, masterKey,
                AccessPolicyExamples.access_policy_example_1, AccessPolicyExamples.access_policy_example_4,
                AccessPolicyExamples.access_policy_example_4_unsatisfied_1, AccessPolicyExamples.access_policy_example_v1, AccessPolicyExamples.access_policy_example_v1);


    }

    //lsss的测试类 重要的测试类
    //attributes 就是一堆属性的合集
    //accesspolicycontrol指定策略访问
    private void try_valid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                         final String accessPolicyString, final String[] attributes, String v, String setv) {
        try {//rho 是根据标志得到属性， attributes是是否符合的属性集合  在多个属性的情况下进行处理
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);//包含v attributes中无需包含v但是最后要加上去
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString); //包含v 使用另一种方式产生rhos
            String[] newattribute = new String[60];
            int count = 0;
            boolean test = false;
            for (String att : attributes) {
                for (String rho : rhos) {
                    if (att.equals(rho.split("-")[0])) {
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
                if (v.equals(rho.split("-")[0])) {
                    v = rho;
                }
                if (setv.equals(rho.split("-")[0])) {
                    setv = rho;
                }
            }
            try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, Arrays.copyOf(newattribute, count), v, setv);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            // System.exit(1);
        }
    }

    private void try_valid_access_policy1(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                          final String oldaccessPolicyString, final String newaccessPolicyString, final String[] attributes, String v, String setv) {
        try {
            int[][] oldaccessPolicy = ParserUtils.GenerateAccessPolicy(oldaccessPolicyString);
            String[] oldrhos = ParserUtils.GenerateRhos(oldaccessPolicyString);
            int[][] newaccessPolicy = ParserUtils.GenerateAccessPolicy(newaccessPolicyString);
            String[] newrhos = ParserUtils.GenerateRhos(newaccessPolicyString);

            String[] newattribute = new String[60];
            int count = 0;
            boolean test = false;
            for (String att : attributes) {
                for (String rho : newrhos) {
                    if (att.equals(rho.split("-")[0])) {
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
            for (String rho : newrhos) {
                if (v.equals(rho.split("-")[0])) {
                    v = rho;
                }
                if (setv.equals(rho.split("-")[0])) {
                    setv = rho;
                }
            }
            try_access_policy_update(pairing, publicKey, masterKey, oldaccessPolicy, oldrhos, newaccessPolicy, newrhos, Arrays.copyOf(newattribute, count), v, setv);
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            //System.exit(1);
        }
    }

    //查看是否符合权限，是否可以访问

    private void try_access_policy_update(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                          final int[][] oldaccessPolicy, final String[] oldrhos, final int[][] newaccessPolicy, final String[] newrhos, final String[] attributes, final String v, final String setv) throws IOException, ClassNotFoundException, UnsatisfiedAccessControlException, InvalidCipherTextException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, attributes, v, setv);//用v生成sk  setv为了验证版本号是否一致
        if (secretKey == null) {
            System.out.println("版本需要更新");
        }
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter) anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        //为了生成相应的加密策略
        PairingCipherSerParameter ciphertext1 = engine.encryption(publicKey, oldaccessPolicy, oldrhos, message, setv); //用setv加密

        PairingCipherSerParameter cipher = engine.updateKeyGen(publicKey, oldaccessPolicy, oldrhos, message, v, newaccessPolicy, newrhos, setv);
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(cipher);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(cipher, anCiphertext);
        cipher = (PairingCipherSerParameter) anCiphertext;

        System.out.println("message=" + message);
        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, newaccessPolicy, newrhos, cipher);
        Assert.assertEquals(message, anMessage);
        System.out.println("anmessage=" + anMessage);
        if (message.equals(anMessage)) {
            System.out.println("更新策略验证成功");
        }

    }


    private void try_invalid_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                           final String accessPolicyString, final String[] attributes, String v, String setv) {
        try {
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);//包含v attributes中无需包含v但是最后要加上去
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString); //包含v 使用另一种方式产生rhos
            String[] newattribute = new String[60];
            int count = 0;
            boolean test = false;
            for (String att : attributes) {
                for (String rho : rhos) {
                    if (att.equals(rho.split("-")[0])) {
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
                if (v.equals(rho.split("-")[0])) {
                    v = rho;
                }
                if (setv.equals(rho.split("-")[0])) {
                    setv = rho;
                }
            }
            try_access_policy(pairing, publicKey, masterKey, accessPolicy, rhos, attributes, v, setv);
        } catch (InvalidCipherTextException e) {
            //correct, expected exception, nothing to do.
        } catch (Exception e) {
            System.out.println("Access policy satisfied test failed, " +
                    "access policy = " + accessPolicyString + ", " +
                    "attributes = " + Arrays.toString(attributes));
            e.printStackTrace();
            //System.exit(1);
        }
    }


    //查看是否符合权限，是否可以访问

    private void try_access_policy(Pairing pairing, PairingKeySerParameter publicKey, PairingKeySerParameter masterKey,
                                   final int[][] accessPolicy, final String[] rhos, final String[] attributes, final String v, final String setv)
            throws InvalidCipherTextException, IOException, ClassNotFoundException, UnsatisfiedAccessControlException {
        //KeyGen and serialization
        PairingKeySerParameter secretKey = engine.keyGen(publicKey, masterKey, attributes, v, setv);//用v生成sk  setv为了验证版本号是否一致
        if (secretKey == null) {
            System.out.println("版本需要更新");
        }
        byte[] byteArraySecretKey = TestUtils.SerCipherParameter(secretKey);
        CipherParameters anSecretKey = TestUtils.deserCipherParameters(byteArraySecretKey);
        Assert.assertEquals(secretKey, anSecretKey);
        secretKey = (PairingKeySerParameter) anSecretKey;

        //Encryption and serialization
        Element message = pairing.getGT().newRandomElement().getImmutable();
        PairingCipherSerParameter ciphertext = engine.encryption(publicKey, accessPolicy, rhos, message, setv); //用setv加密
        byte[] byteArrayCiphertext = TestUtils.SerCipherParameter(ciphertext);
        CipherParameters anCiphertext = TestUtils.deserCipherParameters(byteArrayCiphertext);
        Assert.assertEquals(ciphertext, anCiphertext);
        ciphertext = (PairingCipherSerParameter) anCiphertext;

        System.out.println("message=" + message);
        //Decryption
        Element anMessage = engine.decryption(publicKey, secretKey, accessPolicy, rhos, ciphertext);
        Assert.assertEquals(message, anMessage);
        System.out.println("anmessage=" + anMessage);
        if (message.equals(anMessage)) {
            System.out.println("验证成功");
        }

    }


    public void testLSSSEngine() throws PolicySyntaxException, IOException, ClassNotFoundException {
        this.engine = LSSSCPABE.getInstance();
        engine.setAccessControlEngine(LSSSPolicyEngine.getInstance());
        PairingParameters pairingParameters = PairingFactory.getPairingParameters(TestUtils.TEST_PAIRING_PARAMETERS_PATH_a_80_256);

        //public
        PairingKeySerPair keyPair = engine.setup(pairingParameters, 50);
        PairingKeySerParameter publicKey = keyPair.getPublic();
        byte[] byteArrayPublicKey = TestUtils.SerCipherParameter(publicKey);
        CipherParameters anPublicKey = TestUtils.deserCipherParameters(byteArrayPublicKey);
        Assert.assertEquals(publicKey, anPublicKey);//判断类型是否匹配
        publicKey = (PairingKeySerParameter) anPublicKey;


        //master
        PairingKeySerParameter masterKey = keyPair.getPrivate();
        byte[] byteArrayMasterKey = TestUtils.SerCipherParameter(masterKey);
        CipherParameters anMasterKey = TestUtils.deserCipherParameters(byteArrayMasterKey);
        Assert.assertEquals(masterKey, anMasterKey);
        masterKey = (PairingKeySerParameter) anMasterKey;

        Pairing pairing = PairingFactory.getPairing(pairingParameters);

        runAllTests(pairing, publicKey, masterKey);
    }

}
