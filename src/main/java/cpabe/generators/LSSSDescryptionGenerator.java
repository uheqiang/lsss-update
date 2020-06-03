package cpabe.generators;

import cpabe.access.AccessControlEngine;
import cpabe.access.AccessControlParameter;
import cpabe.access.UnsatisfiedAccessControlException;
import cpabe.genparams.CPABEDecryptionGenerationParameter;
import cpabe.serparams.LSSSCiphertextSerParameter;
import cpabe.serparams.LSSSHeaderSerParameter;
import cpabe.serparams.LSSSPublicKeySerParameter;
import cpabe.serparams.LSSSSecretKeySerParameter;
import cpabe.utils.PairingDecryptionGenerator;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.util.HashMap;
import java.util.Map;

/**
 * @program: lsss
 * @description: 解密的lsss类
 * @author: YST
 * @create: 2020-05-28
 **/
public class LSSSDescryptionGenerator implements PairingDecryptionGenerator {
    private CPABEDecryptionGenerationParameter parameter;
    private Element sessionKey;

    public void init(CipherParameters parameter) {
        this.parameter = (CPABEDecryptionGenerationParameter) parameter;

    }

    private void computeDecapsulation() throws UnsatisfiedAccessControlException {
        LSSSPublicKeySerParameter publicKeyParameter = (LSSSPublicKeySerParameter) this.parameter.getPublicKeyParameter();
        LSSSSecretKeySerParameter secretKeyParameter = (LSSSSecretKeySerParameter) this.parameter.getSecretKeyParameter();
        LSSSHeaderSerParameter ciphertextParameter = (LSSSHeaderSerParameter) this.parameter.getCiphertextParameter();


        AccessControlEngine accessControlEngine = this.parameter.getAccessControlEngine();
        Pairing pairing = PairingFactory.getPairing(publicKeyParameter.getParameters());
        AccessControlParameter accessControlParameter
                = accessControlEngine.generateAccessControl(this.parameter.getAccessPolicy(), this.parameter.getRhos());
        //得到wi
        Map<Integer, String> attributes = new HashMap<Integer, String>();
        attributes.put(0, secretKeyParameter.getVString()[0]);

        for (int i = 0; i < secretKeyParameter.getAttributes().length; i++) {
            attributes.put(i + 1, secretKeyParameter.getAttributes()[i]);
        }
        String v = secretKeyParameter.getVString()[0];
        String[] newattribute = new String[attributes.keySet().size()];
        for (int i = 0; i < newattribute.length; i++) {
            newattribute[i] = attributes.get(i);
            //System.out.println(newattribute[i]);
        }

        //将属性一起加在里面得到wi
        Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, newattribute, accessControlParameter);
        Element L = secretKeyParameter.GetL();
        Element D = secretKeyParameter.GetD();
        Element Dv = secretKeyParameter.getV();//是用户输入的v得到的Dv值
        Element C1v = ciphertextParameter.getC1v();
        Element C2v = ciphertextParameter.getC2v();
        Element C3v = ciphertextParameter.getC3v();
        Element C0 = ciphertextParameter.getC0();
        Element C = ciphertextParameter.getC();
        Element A = pairing.getGT().newOneElement().getImmutable();
        Element F;
        Element part1 = pairing.getZr().newElement(0).getImmutable();//0
        Element part2 = pairing.getGT().newElement(1).getImmutable();//1
        Element part3 = null;
        Element omegav = omegaElementsMap.get(v);
        for (String attribute : omegaElementsMap.keySet()) {
            if (!attribute.equals(v)) {
                Element C1i = ciphertextParameter.getC1iAt(attribute);
                Element C2i = ciphertextParameter.getC2iAt(attribute);
                Element C3i = ciphertextParameter.getC3iAt(attribute);//zr格式
                Element Dj = secretKeyParameter.getDjAt(attribute); //由用户的属性计算出来
                Element omegai = omegaElementsMap.get(attribute);
                part1 = part1.add(C3i.mul(omegai));
                part2 = ((pairing.pairing(C1i, L).mul(pairing.pairing(C2i, Dj))).powZn(omegai)).mul(part2);
                //A = A.mul(pairing.pairing(D1, C1).div(pairing.pairing(D2, C2)).powZn(lambda)).getImmutable();
            }
        }
        part1 = part1.add(C3v.mul(omegav));
        part1 = pairing.pairing(publicKeyParameter.GetG().powZn(part1), L).getImmutable();
        part3 = (pairing.pairing(C1v, L).mul(pairing.pairing(C2v, Dv))).powZn(omegav).getImmutable();
        F = part1.mul(part2).mul(part3);
        sessionKey = F.div(pairing.pairing(D, C));
    }

    public Element recoverMessage() throws InvalidCipherTextException, UnsatisfiedAccessControlException {
        computeDecapsulation();
        LSSSCiphertextSerParameter ciphertextSerParameter = (LSSSCiphertextSerParameter) this.parameter.getCiphertextParameter();
        return ciphertextSerParameter.getCPrime().mul(sessionKey).getImmutable();
    }

    public byte[] recoverKey() throws InvalidCipherTextException, UnsatisfiedAccessControlException {
        computeDecapsulation();
        return this.sessionKey.toBytes();
    }
}
