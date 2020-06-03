package cpabe.serparams;

import cpabe.utils.PairingCipherSerParameter;
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
 * @description: lsss的密文参数类
 * @author: YST
 * @create: 2020-05-28
 **/
public class LSSSHeaderSerParameter extends PairingCipherSerParameter {
    private String[] rhos;
    private transient Element C;

    private final byte[] byteArrayC;
    private transient Element C0;
    private final byte[] byteArrayC0;

    private transient Map<String, Element> C1i;
    private final byte[][] byteArraysC1i;

    private transient Map<String, Element> C2i;
    private final byte[][] byteArraysC2i;

    private transient Map<String, Element> C3i;
    private final byte[][] byteArraysC3i;

    private transient Element C1v;
    private final byte[] byteArrayC1v;

    private transient Element C2v;
    private final byte[] byteArrayC2v;

    private transient Element C3v;
    private final byte[] byteArrayC3v;


    public LSSSHeaderSerParameter(PairingParameters parameters, String[] rhos, Element c, Element c0, Map<String, Element> c1i, Map<String, Element> c2i, Map<String, Element> c3i, Element c1v, Element c2v, Element c3v) {
        super(parameters);
        this.rhos = new String[rhos.length];
        this.rhos = rhos;
        this.C = c.getImmutable();
        this.byteArrayC = this.C.toBytes();

        this.C0 = c0.getImmutable();
        this.byteArrayC0 = this.C0.toBytes();

        this.C1i = new HashMap<String, Element>();
        this.byteArraysC1i = new byte[this.rhos.length][];
        this.C2i = new HashMap<String, Element>();
        this.byteArraysC2i = new byte[this.rhos.length][];
        this.C3i = new HashMap<String, Element>();
        this.byteArraysC3i = new byte[this.rhos.length][];

        this.C1v = c1v.getImmutable();
        this.byteArrayC1v = this.C1v.toBytes();
        this.C2v = c2v.getImmutable();
        this.byteArrayC2v = this.C2v.toBytes();
        this.C3v = c3v.getImmutable();
        this.byteArrayC3v = this.C3v.toBytes();
        for (int i = 0; i < this.rhos.length; i++) {
            Element C1 = c1i.get(this.rhos[i]).duplicate().getImmutable();
            this.C1i.put(this.rhos[i], C1);
            this.byteArraysC1i[i] = C1.toBytes();

            Element C2 = c2i.get(this.rhos[i]).duplicate().getImmutable();
            this.C2i.put(this.rhos[i], C2);
            this.byteArraysC2i[i] = C2.toBytes();

            Element C3 = c3i.get(this.rhos[i]).duplicate().getImmutable();
            this.C3i.put(this.rhos[i], C3);
            this.byteArraysC3i[i] = C3.toBytes();
        }

    }


    public Element getC() {
        return this.C.duplicate();
    }

    public Element getC0() {
        return this.C0.duplicate();
    }

    public Element getC1v() {
        return this.C1v.duplicate();
    }

    public Element getC2v() {
        return this.C2v.duplicate();
    }

    public Element getC3v() {
        return this.C3v.duplicate();
    }

    public Element getC1iAt(String rho) {
        return this.C1i.get(rho).duplicate();
    }

    public Element getC2iAt(String rho) {
        return this.C2i.get(rho).duplicate();
    }

    public Element getC3iAt(String rho) {
        return this.C3i.get(rho).duplicate();
    }

    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof LSSSHeaderSerParameter) {
            LSSSHeaderSerParameter that = (LSSSHeaderSerParameter) anObject;
            //Compare C
            if (!PairingUtils.isEqualElement(this.C, that.C)) {
                System.out.println("11");
                return false;
            }
            if (!Arrays.equals(this.byteArrayC, that.byteArrayC)) {
                System.out.println("22");
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C0, that.C0)) {
                System.out.println("33");
                return false;
            }
            if (!Arrays.equals(this.byteArrayC0, that.byteArrayC0)) {
                System.out.println("4");
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C1v, that.C1v)) {
                System.out.println("5");
                return false;
            }
            if (!Arrays.equals(this.byteArrayC1v, that.byteArrayC1v)) {
                System.out.println("6");
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C2v, that.C2v)) {
                System.out.println("7");
                return false;
            }
            if (!Arrays.equals(this.byteArrayC2v, that.byteArrayC2v)) {
                System.out.println("8");
                return false;
            }
            if (!PairingUtils.isEqualElement(this.C3v, that.C3v)) {
                System.out.println("9");
                return false;
            }
            if (!Arrays.equals(this.byteArrayC3v, that.byteArrayC3v)) {
                System.out.println("10");
                return false;
            }
            //Compare C1s
            if (!this.C1i.equals(that.C1i)) {
                System.out.println("11");
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC1i, that.byteArraysC1i)) {
                System.out.println("12");
                return false;
            }
            //Compare C2s
            if (!this.C2i.equals(that.C2i)) {
                System.out.println("13");
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC2i, that.byteArraysC2i)) {
                System.out.println("14");
                return false;
            }
            //Compare C2s
            if (!this.C3i.equals(that.C3i)) {
                System.out.println("15");
                return false;
            }
            if (!PairingUtils.isEqualByteArrays(this.byteArraysC3i, that.byteArraysC3i)) {
                System.out.println("16");
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
        this.C = pairing.getG1().newElementFromBytes(this.byteArrayC).getImmutable();
        this.C0 = pairing.getG1().newElementFromBytes(this.byteArrayC0).getImmutable();
        this.C1v = pairing.getG1().newElementFromBytes(this.byteArrayC1v).getImmutable();
        this.C2v = pairing.getG1().newElementFromBytes(this.byteArrayC2v).getImmutable();
        this.C3v = pairing.getZr().newElementFromBytes(this.byteArrayC3v).getImmutable();
        this.C1i = new HashMap<String, Element>();
        this.C2i = new HashMap<String, Element>();
        this.C3i = new HashMap<String, Element>();
        for (int i = 0; i < this.rhos.length; i++) {
            this.C1i.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC1i[i]).getImmutable());
            this.C2i.put(this.rhos[i], pairing.getG1().newElementFromBytes(this.byteArraysC2i[i]).getImmutable());
            this.C3i.put(this.rhos[i], pairing.getZr().newElementFromBytes(this.byteArraysC3i[i]).getImmutable());
        }

    }


}
