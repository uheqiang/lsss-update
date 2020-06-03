package cpabe.serparams;

import cpabe.utils.PairingKeySerParameter;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;


/**
 * @program: lsss
 * @description: lsss的master key
 * @author: YST
 * @create: 2020-05-26
 **/
public class LSSSMasterSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element gAlpha;
    private final byte[] byteArrayGAlpha;

    private transient Element Alpha;
    private final byte[] byteArrayAlpha;

    private transient Element gBeta;
    private final byte[] byteArrayGBeta;


    public LSSSMasterSecretKeySerParameter(PairingParameters pairingParameters, Element gAlpha, Element Alpha, Element gbeta) {
        super(true, pairingParameters);
        this.gAlpha = gAlpha.getImmutable();
        this.byteArrayGAlpha = this.gAlpha.toBytes();
        this.Alpha = Alpha.getImmutable();
        this.byteArrayAlpha = this.Alpha.toBytes();
        this.gBeta = gbeta.getImmutable();
        this.byteArrayGBeta = this.gBeta.toBytes();
    }

    public Element getgAlpha() {
        return gAlpha;
    }

    public Element getAlpha() {
        return Alpha;
    }

    public Element getGBeta() {
        return gBeta;
    }


    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof LSSSMasterSecretKeySerParameter) {
            LSSSMasterSecretKeySerParameter that = (LSSSMasterSecretKeySerParameter) anObject;
            //compare gAlpha
            if (!(PairingUtils.isEqualElement(this.Alpha, that.Alpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayAlpha, that.byteArrayAlpha)) {
                return false;
            }
            //compare beta
            if (!(PairingUtils.isEqualElement(this.gBeta, that.gBeta))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGBeta, that.byteArrayGBeta)) {
                return false;
            }
            //compare beta
            if (!(PairingUtils.isEqualElement(this.gAlpha, that.gAlpha))) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayGAlpha, that.byteArrayGAlpha)) {
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }

    private void readObject(java.io.ObjectInputStream objectInputStream)
            throws java.io.IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        Pairing pairing = PairingFactory.getPairing(this.getParameters());
        this.gAlpha = pairing.getG1().newElementFromBytes(this.byteArrayGAlpha).getImmutable();
        this.Alpha = pairing.getZr().newElementFromBytes(this.byteArrayAlpha).getImmutable();
        this.gBeta = pairing.getG1().newElementFromBytes(this.byteArrayGBeta).getImmutable();
    }


}
