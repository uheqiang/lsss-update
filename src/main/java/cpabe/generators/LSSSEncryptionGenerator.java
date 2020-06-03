package cpabe.generators;

import cpabe.access.AccessControlEngine;
import cpabe.access.AccessControlParameter;
import cpabe.genparams.CPABEncryptionGenerationParameter;
import cpabe.serparams.LSSSCiphertextSerParameter;
import cpabe.serparams.LSSSPublicKeySerParameter;
import cpabe.utils.PairingEncriptionGenerator;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * @program: lsss
 * @description: encryption()的加密函数
 * @author: YST
 * @create: 2020-05-27
 **/
public class LSSSEncryptionGenerator implements PairingEncriptionGenerator {
    //加密类
    private CPABEncryptionGenerationParameter parameter;
    private LSSSPublicKeySerParameter publicKeyParameter;

    private Element C;

    private Element C0;

    private String[] rhos;
    private String[] rhom;

    private Map<String, Element> C1i;
    private Map<String, Element> C2i;
    private Map<String, Element> C3i;

    private Element C1v;
    private Element C2v;
    private Element C3v;

    String v;
    private Map<String, Element> lambdass = new HashMap<String, Element>();
    private Map<String, Element> lambdassp = new HashMap<String, Element>();
    private Map<String, Element> rowis = new HashMap<String, Element>();

    public LSSSEncryptionGenerator() {
    }


    //为了更新策略新加的属性


    public void init(CipherParameters parameter) {
        this.parameter = (CPABEncryptionGenerationParameter) parameter;
        this.publicKeyParameter = (LSSSPublicKeySerParameter) this.parameter.getPublicKeyParameter();
    }

    private void computeEncrtption() {
        //构造树的方式按照版本号来构造
        int[][] accessPolicy = this.parameter.getAccessPolicy();
        rhos = this.parameter.getRhos();
        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);//生成的矩阵M
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        v = this.parameter.getV();//set v
        //公共加密的元素s
        Element s = pairing.getZr().newRandomElement().getImmutable();
        this.C = publicKeyParameter.GetG().powZn(s).getImmutable();
        this.C0 = publicKeyParameter.getEggAlpha().powZn(s).getImmutable();//session key 不是最后计算的ck*e(g,g)
        Map<String, Element> lambdas = accessControlEngine.secretSharing(pairing, s, accessControlParameter);//生成入i 第一个给v命名为lamdav   即使是重复的也要生成
        //解密的时候需要omegai   Map<String, Element> omegai = accessControlEngine.reconstructOmegas(pairing,,accessControlParameter)
        this.C1i = new HashMap<String, Element>();
        this.C2i = new HashMap<String, Element>();
        this.C3i = new HashMap<String, Element>();
        for (String rho : lambdas.keySet()) {
            //lambdas.get(rho) 相当于lamdai
            Element ri = pairing.getZr().newRandomElement().getImmutable();
            Element lamdasi = lambdas.get(rho);
            Element lamdasip = pairing.getZr().newRandomElement().getImmutable();
            //   Element pi = pairing.getZr().newRandomElement().getImmutable();
            Element pi = PairingUtils.MapStringToGroup(pairing, rho, PairingUtils.PairingGroupType.Zr);
            rowis.put(rho, pi);
            lambdass.put(rho, lamdasi);
            lambdassp.put(rho, lamdasip);
            if (v.split("-")[0].equals(rho.split("-")[0])) {//(publicKeyParameter.getH().powZn(lamdasip)).mul(
                this.C1v = (publicKeyParameter.getH().powZn(lamdasip)).mul(publicKeyParameter.GetG().powZn(pi.mul(ri.negate()))).getImmutable();
                this.C2v = publicKeyParameter.GetG().powZn(ri).getImmutable();
                this.C3v = (publicKeyParameter.getB()).mul(lamdasi.sub(lamdasip)).getImmutable();
                //    System.out.println(this.C1v);
                //   System.out.println(this.C2v);
                //  System.out.println(this.C3v);

            } else {//rho 代表了属性的值
                this.C1i.put(rho, (publicKeyParameter.getH().powZn(lamdasip)).mul(publicKeyParameter.GetG().powZn(pi.mul(ri.negate()))).getImmutable());
                this.C2i.put(rho, publicKeyParameter.GetG().powZn(ri).getImmutable());
                this.C3i.put(rho, publicKeyParameter.getB().mul(lamdasi.sub(lamdasip)).getImmutable());
            }
        }
        rhom = new String[rhos.length - 1];
        for (int i = 0, j = 0; j < rhos.length; j++) {
            if (rhos[j].split("-")[0].equals(v.split("-")[0])) {
                continue;
            }
            rhom[i] = rhos[j];
            i++;

        }
    }

    public LSSSCiphertextSerParameter generateCiphertext() {
        computeEncrtption();
        Element CPrime = this.C0.mul(this.parameter.getMessage()).getImmutable();//密文
        return new LSSSCiphertextSerParameter(publicKeyParameter.getParameters(), CPrime, rhom, C, C0, C1i, C2i, C3i, C1v, C2v, C3v);
    }

    public Map<String, Element> returnLambda() {
        return lambdass;
    }

    public Map<String, Element> returnrow() {
        return rowis;
    }

    public Map<String, Element> returnC1i() {
        return this.C1i;
    }

    public Map<String, Element> returnC2i() {
        return this.C2i;
    }

    public Map<String, Element> returnC3i() {
        return this.C3i;
    }

    public Map<String, Element> returnLambdap() {
        return lambdassp;
    }

}
