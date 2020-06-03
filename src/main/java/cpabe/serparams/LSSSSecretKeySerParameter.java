package cpabe.serparams;

import cpabe.utils.PairingKeySerParameter;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @program: lsss
 * @description: lsss生成secretkey
 * @author: YST
 * @create: 2020-05-26
 **/
public class LSSSSecretKeySerParameter extends PairingKeySerParameter {
    private transient Element D;
    private final byte[] byteArrayD;
    private transient Element L;
    private final byte[] byteArrayL;
    private transient Map<String, Element> Dj;
    private final Map<String, byte[]> byteArraysDj;
    private transient Map<String, Element> Dv;
    private final Map<String, byte[]> byteArrayDv;

    public LSSSSecretKeySerParameter(PairingParameters pairingParameters, Element D, Element L, Map<String, Element> Dj, Map<String, Element> Dv) {
        super(true, pairingParameters);
        this.D = D.getImmutable();
        this.byteArrayD = this.D.toBytes();
        this.L = L.getImmutable();
        this.byteArrayL = this.L.toBytes();
        this.Dv = new HashMap<String, Element>();
        this.byteArrayDv = new HashMap<String, byte[]>();
        for (String attribute : Dv.keySet()) {
            this.Dv.put(attribute, Dv.get(attribute).duplicate().getImmutable());
            this.byteArrayDv.put(attribute, Dv.get(attribute).duplicate().getImmutable().toBytes());
        }
        this.Dj = new HashMap<String, Element>();
        this.byteArraysDj = new HashMap<String, byte[]>();
        for (String attribute : Dj.keySet()) {
            this.Dj.put(attribute, Dj.get(attribute).duplicate().getImmutable());
            this.byteArraysDj.put(attribute, Dj.get(attribute).duplicate().getImmutable().toBytes());
        }
    }

    public Element GetD() {
        return this.D.duplicate();
    }

    public Element GetL() {
        return this.L.duplicate();
    }

    public Element getDvAt(String v) {
        return this.Dv.get(v).duplicate();
    }

    //从访问策略中得到用户设置的版本号 ，将版本号放在第一个位置
    public Element getV() {
        return this.Dv.get(this.Dv.keySet().toArray(new String[1])[0]);
    }

    public String[] getVString() {
        return this.Dv.keySet().toArray(new String[1]);
    }

    public String[] getAttributes() {
        return this.Dj.keySet().toArray(new String[1]);
    }

    public Element getDjAt(String attribute) {
        return this.Dj.get(attribute).duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof LSSSSecretKeySerParameter) {
            LSSSSecretKeySerParameter that = (LSSSSecretKeySerParameter) anObject;
            //Compare D
            if (!PairingUtils.isEqualElement(this.D, that.D)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayD, that.byteArrayD)) {
                return false;
            }
            //Compare D
            if (!PairingUtils.isEqualElement(this.L, that.L)) {
                return false;
            }
            if (!Arrays.equals(this.byteArrayL, that.byteArrayL)) {
                return false;
            }
            //Compare D
            if (!this.Dv.equals(that.Dv)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArrayDv, that.byteArrayDv)) {
                return false;
            }
            //compare D1s
            if (!this.Dj.equals(that.Dj)) {
                return false;
            }
            if (!PairingUtils.isEqualByteArrayMaps(this.byteArraysDj, that.byteArraysDj)) {
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
        this.D = pairing.getG1().newElementFromBytes(this.byteArrayD);
        this.L = pairing.getG1().newElementFromBytes(this.byteArrayL);
        this.Dv = new HashMap<String, Element>();
        for (String attribute : this.byteArrayDv.keySet()) {
            this.Dv.put(attribute, pairing.getG1().newElementFromBytes(this.byteArrayDv.get(attribute)).getImmutable());
        }
        this.Dj = new HashMap<String, Element>();
        for (String attribute : this.byteArraysDj.keySet()) {
            this.Dj.put(attribute, pairing.getG1().newElementFromBytes(this.byteArraysDj.get(attribute)).getImmutable());
        }
    }


}
