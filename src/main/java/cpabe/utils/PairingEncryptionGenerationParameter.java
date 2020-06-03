package cpabe.utils;

import it.unisa.dia.gas.jpbc.Element;

/**
 * @program: lsss
 * @description: 生成encrypt的抽象类
 * @author: YST
 * @create: 2020-05-27
 **/
public class PairingEncryptionGenerationParameter extends PairingEncapsulationGenerationParameter {
    private Element message;
    private String v;

    public PairingEncryptionGenerationParameter(PairingKeySerParameter publicKeyParameter, Element message, String v) {
        super(publicKeyParameter);
        if (message != null) {
            //parameter for encryption.
            this.message = message.getImmutable();
        }
        if (v != null) {
            this.v = v;
        }
    }

    public Element getMessage() {
        if (message == null) {
            return null;
        }
        return this.message.duplicate();
    }

    public String getV() {
        if (v == null) {
            return null;
        }
        return v;
    }
}
