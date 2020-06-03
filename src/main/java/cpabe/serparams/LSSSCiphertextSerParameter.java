package cpabe.serparams;

import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.Map;

/**
 * @program: lsss
 * @description: 生成lsss的ciphertext
 * @author: YST
 * @create: 2020-05-26
 **/
public class LSSSCiphertextSerParameter extends LSSSHeaderSerParameter {
    private transient Element CPrime;
    private final byte[] byteArrayCPrime;


    public LSSSCiphertextSerParameter(PairingParameters parameters, Element CPrime, String[] rhos, Element c, Element c0, Map<String, Element> c1i, Map<String, Element> c2i, Map<String, Element> c3i, Element c1v, Element c2v, Element c3v) {
        super(parameters, rhos, c, c0, c1i, c2i, c3i, c1v, c2v, c3v);
        this.CPrime = CPrime.getImmutable();
        this.byteArrayCPrime = this.CPrime.toBytes();
    }

    public Element getCPrime() {
        return this.CPrime.duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof LSSSCiphertextSerParameter) {
            LSSSCiphertextSerParameter that = (LSSSCiphertextSerParameter) anObject;
            return PairingUtils.isEqualElement(this.CPrime, that.CPrime)
                    && Arrays.equals(this.byteArrayCPrime, that.byteArrayCPrime)
                    && super.equals(anObject);
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.CPrime = pairing.getGT().newElementFromBytes(this.byteArrayCPrime).getImmutable();
    }
}
