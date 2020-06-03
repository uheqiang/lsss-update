package cpabe.genparams;

import cpabe.access.AccessControlEngine;
import cpabe.hashutil.ChameleonHasher;
import cpabe.utils.AsymmetricKeySerPairGenerator;
import cpabe.utils.PairingCipherSerParameter;
import cpabe.utils.PairingKeySerParameter;
import cpabe.utils.PairingReEncryptionGenerationParameter;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @program: lsss
 * @description:
 * @author: YST
 * @create: 2020-05-29
 **/
public class CPABEREencryptionGenerationParameter extends PairingReEncryptionGenerationParameter {
    private AccessControlEngine accessControlEngine;//访问权限
    private int[][] oldaccessPolicy;
    private String[] oldrhos;
    private int[][] newaccessPolicy;
    private String[] newrhos;
    private ChameleonHasher chameleonHasher;
    private AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator;
    private KeyGenerationParameters chameleonHashKeyPairGenerationParameter;
    private PairingCipherSerParameter intermediate;


    public AccessControlEngine getAccessControlEngine() {
        return accessControlEngine;
    }

    public void setAccessControlEngine(AccessControlEngine accessControlEngine) {
        this.accessControlEngine = accessControlEngine;
    }

    public int[][] getOldaccessPolicy() {
        return oldaccessPolicy;
    }

    public void setOldaccessPolicy(int[][] oldaccessPolicy) {
        this.oldaccessPolicy = oldaccessPolicy;
    }

    public String[] getOldrhos() {
        return oldrhos;
    }

    public void setOldrhos(String[] oldrhos) {
        this.oldrhos = oldrhos;
    }

    public int[][] getNewaccessPolicy() {
        return newaccessPolicy;
    }

    public void setNewaccessPolicy(int[][] newaccessPolicy) {
        this.newaccessPolicy = newaccessPolicy;
    }

    public String[] getNewrhos() {
        return newrhos;
    }

    public void setNewrhos(String[] newrhos) {
        this.newrhos = newrhos;
    }

    public ChameleonHasher getChameleonHasher() {
        return chameleonHasher;
    }

    public void setChameleonHasher(ChameleonHasher chameleonHasher) {
        this.chameleonHasher = chameleonHasher;
    }

    public AsymmetricKeySerPairGenerator getChameleonHashKeyPairGenerator() {
        return chameleonHashKeyPairGenerator;
    }

    public void setChameleonHashKeyPairGenerator(AsymmetricKeySerPairGenerator chameleonHashKeyPairGenerator) {
        this.chameleonHashKeyPairGenerator = chameleonHashKeyPairGenerator;
    }

    public KeyGenerationParameters getChameleonHashKeyPairGenerationParameter() {
        return chameleonHashKeyPairGenerationParameter;
    }

    public void setChameleonHashKeyPairGenerationParameter(KeyGenerationParameters chameleonHashKeyPairGenerationParameter) {
        this.chameleonHashKeyPairGenerationParameter = chameleonHashKeyPairGenerationParameter;
    }

    public PairingCipherSerParameter getIntermediate() {
        return intermediate;
    }

    public void setIntermediate(PairingCipherSerParameter intermediate) {
        this.intermediate = intermediate;
    }

    public CPABEREencryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, Element message, String v, String newV, AccessControlEngine accessControlEngine, int[][] oldaccessPolicy, String[] oldrhos, int[][] newaccessPolicy, String[] newrhos) {
        super(publicKeyParameter, message, v, newV);
        this.accessControlEngine = accessControlEngine;
        this.oldaccessPolicy = oldaccessPolicy;
        this.oldrhos = oldrhos;
        this.newaccessPolicy = newaccessPolicy;
        this.newrhos = newrhos;
    }
}
