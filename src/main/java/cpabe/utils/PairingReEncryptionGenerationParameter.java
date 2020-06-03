package cpabe.utils;

import it.unisa.dia.gas.jpbc.Element;

/**
 * @program: lsss
 * @description: 更新策略的密钥类
 * @author: YST
 * @create: 2020-05-29
 **/
public class PairingReEncryptionGenerationParameter extends PairingEncapsulationGenerationParameter {
    private Element message;
    private String v;
    private String newV;

    public PairingReEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, Element message, String v, String newV) {
        super(publicKeyParameter);
        if (message != null) {
            //parameter for encryption.
            this.message = message.getImmutable();
        }
        if (v != null) {
            this.v = v;
        }
        if (newV != null) {
            this.newV = newV;
        }
    }

    public String getV() {
        if (v == null) {
            return null;
        }
        return v;
    }

    public Element getMessage() {
        if (message == null) {
            return null;
        }
        return this.message.duplicate();
    }

    public String getNewV() {
        if (newV == null) {
            return null;
        }
        return newV;
    }
}
