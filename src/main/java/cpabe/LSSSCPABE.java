package cpabe;

import cpabe.access.AccessControlEngine;
import cpabe.access.UnsatisfiedAccessControlException;
import cpabe.generators.*;
import cpabe.genparams.*;
import cpabe.serparams.LSSSCiphertextSerParameter;
import cpabe.serparams.LSSSMasterSecretKeySerParameter;
import cpabe.serparams.LSSSPublicKeySerParameter;
import cpabe.serparams.LSSSSecretKeySerParameter;
import cpabe.utils.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.Map;

/**
 * @program: lsss
 * @description: lsss实现的cp-abe
 * @author: YST
 * @create: 2020-05-26
 **/
public class LSSSCPABE extends CPABE {
    protected AccessControlEngine accessControlEngine = AccessTreeEngine.getInstance();
    private static LSSSCPABE engine;

    //更新策略的处理
    private Map<String, Element> lambdass;
    private Map<String, Element> lambdassp;
    private Map<String, Element> rowis;
    private Map<String, Element> C1i;
    private Map<String, Element> C2i;
    private Map<String, Element> C3i;

    public static LSSSCPABE getInstance() {
        if (engine == null) {
            engine = new LSSSCPABE();
        }
        return engine;
    }

    public void setAccessControlEngine(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
    }

    public boolean isAccessControlEngineSupportThresholdGate() {
        return this.accessControlEngine.isSupportThresholdGate();
    }


    private LSSSCPABE() {
        super();
    }

    public PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum) {
        LSSSKeyPairGenerator keyPairGenerator = new LSSSKeyPairGenerator();
        keyPairGenerator.init(new CPABEKeyPairGenerationParameter(pairingParameters));
        return keyPairGenerator.generateKeyPair();
    }

    public PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes, String v, String v_set) {
        if (!(publicKey instanceof LSSSPublicKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(publicKey, LSSSPublicKeySerParameter.class.getName());
        }
        if (!(masterKey instanceof LSSSMasterSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(masterKey, LSSSMasterSecretKeySerParameter.class.getName());
        }
        LSSSSecretKeyGenerator secretKeyGenerator = new LSSSSecretKeyGenerator();
        secretKeyGenerator.init(new CPABESecretKeyGenerationParameter(publicKey, masterKey, attributes, v), new CPABEncryptionGenerationParameter(accessControlEngine, publicKey, null, null, null, v_set));
        if (secretKeyGenerator.verifyVersion()) {
            return secretKeyGenerator.generateKey();
        } else {
            return null;
        }
    }

    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message, String v) {//输入版本号
        if (!(publicKey instanceof LSSSPublicKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(publicKey, LSSSPublicKeySerParameter.class.getName());
        }
        LSSSEncryptionGenerator encryptionGenerator = new LSSSEncryptionGenerator();
        encryptionGenerator.init(new CPABEncryptionGenerationParameter(accessControlEngine, publicKey, message, accessPolicyIntArrays, rhos, v));
        PairingCipherSerParameter parameter = encryptionGenerator.generateCiphertext();
        lambdass = encryptionGenerator.returnLambda();
        lambdassp = encryptionGenerator.returnLambdap();
        rowis = encryptionGenerator.returnrow();
        C1i = encryptionGenerator.returnC1i();
        C2i = encryptionGenerator.returnC2i();
        C3i = encryptionGenerator.returnC3i();
        return parameter;
    }

    public Element decryption(PairingKeySerParameter publicKey, PairingKeySerParameter secretKey,
                              int[][] accessPolicyIntArrays, String[] rhos, PairingCipherSerParameter ciphertext) throws UnsatisfiedAccessControlException, InvalidCipherTextException {
        if (!(publicKey instanceof LSSSPublicKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(publicKey, LSSSPublicKeySerParameter.class.getName());
        }
        if (!(secretKey instanceof LSSSSecretKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(secretKey, LSSSSecretKeySerParameter.class.getName());
        }
        if (!(ciphertext instanceof LSSSCiphertextSerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(ciphertext, LSSSCiphertextSerParameter.class.getName());
        }
        LSSSDescryptionGenerator decryptionGenerator = new LSSSDescryptionGenerator();
        decryptionGenerator.init(new CPABEDecryptionGenerationParameter(
                accessControlEngine, publicKey, secretKey, accessPolicyIntArrays, rhos, ciphertext));
        return decryptionGenerator.recoverMessage();
    }


    //密钥更新之后的密文更新策略
    public PairingCipherSerParameter updateKeyGen(PairingKeySerParameter publicKey, int[][] oldaccessPolicyIntArrays, String[] oldrhos, Element message, String v, int[][] newaccessPolicyIntArrays, String[] newrhos, String newV) {
        if (!(publicKey instanceof LSSSPublicKeySerParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(publicKey, LSSSPublicKeySerParameter.class.getName());
        }
        LSSSUpdateKeyGenGenerator updateKeyGenGenerator = new LSSSUpdateKeyGenGenerator(lambdass, lambdassp, rowis, C1i, C2i, C3i);
        updateKeyGenGenerator.init(new CPABEREencryptionGenerationParameter(publicKey, message, v, newV, accessControlEngine, oldaccessPolicyIntArrays, oldrhos, newaccessPolicyIntArrays, newrhos));
        lambdass = updateKeyGenGenerator.returnLambda();
        lambdassp = updateKeyGenGenerator.returnLambdap();
        C1i = updateKeyGenGenerator.returnC1i();
        C2i = updateKeyGenGenerator.returnC2i();
        C3i = updateKeyGenGenerator.returnC3i();
        rowis = updateKeyGenGenerator.returnrow();
        return updateKeyGenGenerator.generateCiphertext();
    }

}
