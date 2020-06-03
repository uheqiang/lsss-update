package cpabe.generators;

import cpabe.access.AccessControlEngine;
import cpabe.access.AccessControlParameter;
import cpabe.genparams.CPABEREencryptionGenerationParameter;
import cpabe.serparams.LSSSCiphertextSerParameter;
import cpabe.serparams.LSSSPublicKeySerParameter;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * @program: lsss
 * @description: 对于更新策略的类
 * @author: YST
 * @create: 2020-05-29
 **/
public class LSSSUpdateKeyGenGenerator {
    private CPABEREencryptionGenerationParameter parameter;
    private LSSSPublicKeySerParameter publicKeyParameter;
    private String[] rhos;
    private String[] newrhos;
    String v;
    String newV;

    //更新策略
    private Map<String, Element> lambdass;
    private Map<String, Element> rowis;
    private Map<String, Element> lambdassp;

    public LSSSUpdateKeyGenGenerator(Map<String, Element> lambdass, Map<String, Element> lambdassp, Map<String, Element> rowis, Map<String, Element> C1i, Map<String, Element> C2i, Map<String, Element> C3i) {
        this.lambdass = lambdass;
        this.lambdassp = lambdassp;
        this.rowis = rowis;
        this.C1i = C1i;
        this.C2i = C2i;
        this.C3i = C3i;
    }

    private Element C;
    private Element C0;

    private Map<String, Element> C1i;
    private Map<String, Element> C2i;
    private Map<String, Element> C3i;

    //更新的密钥
    private Map<String, Element> U1i;
    private Map<String, Element> U2i;
    private Map<String, Element> U3i;
    //更新的密文
    private Map<String, Element> C1j;
    private Map<String, Element> C2j;
    private Map<String, Element> C3j;


    private Map<String, Element> lambdassnew = new HashMap<String, Element>();
    private Map<String, Element> rowisnew = new HashMap<String, Element>();
    private Map<String, Element> lambdassnewp = new HashMap<String, Element>();

    private Element C1v;
    private Element C2v;
    private Element C3v;

    private String[] rhom;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEREencryptionGenerationParameter) parameter;
        this.publicKeyParameter = (LSSSPublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    private void computeEncrtption() {
        int[][] accessPolicy = this.parameter.getOldaccessPolicy();
        rhos = this.parameter.getOldrhos();//和旧的策略之间相差一些数据
        int[][] newaccessPolicy = this.parameter.getNewaccessPolicy();
        newrhos = this.parameter.getNewrhos();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        v = this.parameter.getV();
        newV = this.parameter.getNewV();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.U1i = new HashMap<String, Element>();
        this.U2i = new HashMap<String, Element>();
        this.U3i = new HashMap<String, Element>();

        this.C1j = new HashMap<String, Element>();
        this.C2j = new HashMap<String, Element>();
        this.C3j = new HashMap<String, Element>();

        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(newaccessPolicy, newrhos);//生成的矩阵M
        //生成新的策略
        Map<String, Element> lambdasnew = accessControlEngine.secretSharing(pairing, s, accessControlParameter);

        this.C = publicKeyParameter.GetG().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();
        //  Map<String, Integer> temp = new HashMap<String, Integer>();
        int temp = 0;


        int total = 0;//为了type2设置的变量
        //1 去重
     /*   Set<String> rhos1 = new HashSet<String>();
        for (int i = 0; i < newrhos.length; i++) {
            rhos1.add(newrhos[i]);
        }
        System.out.println(rhos1);*/


        for (String newrho : newrhos) {
            //     System.out.println(newrhos.length); //一共有7个
            //   System.out.println(rhos.length);//一共5个
            //计算版本号
            if (newrho.equals(newV)) {//(publicKeyParameter.getH().powZn(lamdasip)).mul(
                Element lamdasi = lambdasnew.get(newrho);
                Element lamdasip = pairing.getZr().newRandomElement().getImmutable();
                Element ri = pairing.getZr().newRandomElement().getImmutable();
                //   Element pi = pairing.getZr().newRandomElement().getImmutable();
                Element pi = PairingUtils.MapStringToGroup(pairing, newrho, PairingUtils.PairingGroupType.Zr);
                this.C1v = (publicKeyParameter.getH().powZn(lamdasip)).mul(publicKeyParameter.GetG().powZn(pi.mul(ri.negate()))).getImmutable();
                this.C2v = publicKeyParameter.GetG().powZn(ri).getImmutable();
                this.C3v = (publicKeyParameter.getB()).mul(lamdasi.sub(lamdasip)).getImmutable();
                //    lambdasnew.put(newrho, lamdasi);
                rowisnew.put(newrho, pi);
                lambdassnewp.put(newrho, lamdasip);
                //*       System.out.println(this.C1v);
                //      System.out.println(this.C2v);
                //    System.out.println(this.C3v);*//*
                continue;
            }
            for (String rho : rhos) {
                if (newrho.equals(rho)) {
                    for (String rho1 : newrhos) {//原来2个属性，现在1个属性
                        if (newrho.equals(rho1)) {
                            temp++;
                        }
                    }
                }
            }
            if (temp == 0) {//Type3
                Element lamdasj = lambdasnew.get(newrho);
                Element lamdasjp = pairing.getZr().newRandomElement().getImmutable();
                Element pj = PairingUtils.MapStringToGroup(pairing, newrho, PairingUtils.PairingGroupType.Zr);
                Element rj = pairing.getZr().newRandomElement().getImmutable();
                //更新密钥
                U1i.put(newrho, publicKeyParameter.getH().powZn(lamdasjp).mul(publicKeyParameter.GetG().powZn(pj.mul(rj.negate()))).getImmutable());
                U2i.put(newrho, publicKeyParameter.GetG().powZn(rj).getImmutable());
                U3i.put(newrho, publicKeyParameter.getB().mul(lamdasj.sub(lamdasjp)).getImmutable());
                //更新密文
                C1j = U1i;
                C2j = U2i;
                C3j = U3i;
                //    lambdasnew.put(newrho, lamdasj);
                rowisnew.put(newrho, pj);
                lambdassnewp.put(newrho, lamdasjp);
            }
            if (temp == 1) { //Type1
                //     System.out.println("-----" + C1i.get(newrho));
                //更新密钥
                String ltemp = null;
                for (String rho : rhos) {
                    if (rho.split("-")[0].equals(newrho.split("-")[0])) {
                        ltemp = rho;
                    }
                }
                U1i.put(newrho, C1i.get(ltemp));
                U2i.put(newrho, C2i.get(ltemp));
                U3i.put(newrho, publicKeyParameter.getB().mul(lambdasnew.get(newrho).sub(lambdass.get(ltemp))));
                //更新密文
                C1j = U1i;
                C2j = U2i;
                C3j.put(newrho, U3i.get(newrho).add(C3i.get(ltemp)));


                //  lambdasnew.put(newrho, lambdass.get(newrho));
                rowisnew.put(newrho, rowis.get(newrho));
                lambdassnewp.put(newrho, lambdassp.get(newrho));
            }
            if (temp > 1) {//Type2  //把新策略中的相应的苏属性去掉多余的只保留一个

                //更新密钥
                Element alphaj = pairing.getZr().newRandomElement().getImmutable();
                Element lamdajp = pairing.getZr().newRandomElement().getImmutable();
                U1i.put(newrho, alphaj);
                U2i.put(newrho, publicKeyParameter.getB().mul(lamdajp.sub(alphaj.mul(lambdassp.get(newrho)))));
                U3i.put(newrho, publicKeyParameter.getB().mul(lambdasnew.get(newrho).sub(lamdajp)));
                //    lambdasnew.put(newrho, lambdass.get(newrho));
                C1j.put(newrho, C1i.get(newrho).powZn(alphaj).mul(publicKeyParameter.GetG().powZn(U2i.get(newrho))));
                C2j.put(newrho, C2i.get(newrho).powZn(alphaj));
                C3j.put(newrho, U3i.get(newrho));
                rowisnew.put(newrho, rowis.get(newrho));
                lambdassnewp.put(newrho, lamdajp);

            }
            temp = 0;
        }
        rhom = new String[newrhos.length - 1];
        for (int i = 0, j = 0; j < newrhos.length; j++) {
            if (newrhos[j].equals(newV)) {
                continue;
            }
            rhom[i] = newrhos[j];
            //     System.out.println(rhom[i]);
            i++;
        }
    }

    public LSSSCiphertextSerParameter generateCiphertext() {
        computeEncrtption();
        Element CPrime = this.C0.mul(this.parameter.getMessage()).getImmutable();//密文
        return new LSSSCiphertextSerParameter(publicKeyParameter.getParameters(), CPrime, rhom, C, C0, C1j, C2j, C3j, C1v, C2v, C3v);
    }

    public Map<String, Element> returnLambda() {
        return lambdassnew;
    }

    public Map<String, Element> returnrow() {
        return rowisnew;
    }

    public Map<String, Element> returnC1i() {
        return C1j;
    }

    public Map<String, Element> returnC2i() {
        return C2j;
    }

    public Map<String, Element> returnC3i() {
        return C3j;
    }

    public Map<String, Element> returnLambdap() {
        return lambdassnewp;
    }
}
