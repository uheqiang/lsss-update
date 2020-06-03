package cpabe.genparams;

import cpabe.access.AccessControlEngine;
import cpabe.hashutil.ChameleonHasher;
import cpabe.utils.AsymmetricKeySerPairGenerator;
import cpabe.utils.PairingCipherSerParameter;
import cpabe.utils.PairingEncryptionGenerationParameter;
import cpabe.utils.PairingKeySerParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @program: lsss
 * @description: cpabe 的加密类
 * @author: YST
 * @create: 2020-05-27
 **/
public class CPABEncryptionGenerationParameter extends PairingEncryptionGenerationParameter {
    private AccessControlEngine accessControlEngine;//访问权限
    private int[][] accessPolicy;
    private String[] rhos;
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyPairGenerationParameter;
    private PairingCipherSerParameter intermediate;

    public void setIntermediate(PairingCipherSerParameter intermediate) {
        this.intermediate = intermediate;
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator keyPairGenerator) {
        this.chameleonHashKeyPairGenerator = keyPairGenerator;
    }

    public void setChameleonHashKeyPairGenerationParameter(KeyGenerationParameters keyGenerationParameters) {
        this.chameleonHashKeyPairGenerationParameter = keyGenerationParameters;
    }

    public AccessControlEngine getAccessControlEngine() {
        return this.accessControlEngine;
    }

    public int[][] getAccessPolicy() {
        return this.accessPolicy;
    }

    public String[] getRhos() {
        return this.rhos;
    }

    public ChameleonHasher getChameleonHasher() {
        return this.chameleonHasher;
    }

    public boolean isIntermediateGeneration() {
        return (this.intermediate != null);
    }

    public PairingCipherSerParameter getIntermediate() {
        return this.intermediate;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return this.chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyPairGenerationParameter() {
        return this.chameleonHashKeyPairGenerationParameter;
    }

    public CPABEncryptionGenerationParameter(AccessControlEngine accessControlEngine, PairingKeySerParameter publicKeyParameter, Element message, int[][] accessPolicy, String[] rhos, String v) {
        super(publicKeyParameter, message, v);
        this.accessControlEngine = accessControlEngine;
        this.accessPolicy = accessPolicy;
        this.rhos = rhos;
    }
}
