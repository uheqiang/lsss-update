package cpabe.generators;

import cpabe.genparams.CPABESecretKeyGenerationParameter;
import cpabe.genparams.CPABEncryptionGenerationParameter;
import cpabe.serparams.LSSSMasterSecretKeySerParameter;
import cpabe.serparams.LSSSPublicKeySerParameter;
import cpabe.serparams.LSSSSecretKeySerParameter;
import cpabe.utils.PairingKeyParameterGenerator;
import cpabe.utils.PairingKeySerParameter;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.util.HashMap;
import java.util.Map;

/**
 * @program: lsss
 * @description: keygen得到的secretkey
 * @author: YST
 * @create: 2020-05-27
 **/
public class LSSSSecretKeyGenerator implements PairingKeyParameterGenerator {
    private CPABESecretKeyGenerationParameter parameter;//通过属性生成私钥
    private CPABEncryptionGenerationParameter verifyparameter;//验证的加密信息

    public void init(KeyGenerationParameters keyGenerationParameters, CipherParameters parameter) {
        this.parameter = (CPABESecretKeyGenerationParameter) keyGenerationParameters;
        this.verifyparameter = (CPABEncryptionGenerationParameter) parameter;//为了进行验证
    }

    public PairingKeySerParameter generateKey() {
        LSSSMasterSecretKeySerParameter masterSecretKeySerParameter = (LSSSMasterSecretKeySerParameter) parameter.getMasterSecretKeyParameter();
        LSSSPublicKeySerParameter publicKeySerParameter = (LSSSPublicKeySerParameter) parameter.getPublicKeyParameter();

        String[] attributes = this.parameter.getAttributes();
        Pairing pairing = PairingFactory.getPairing(publicKeySerParameter.getParameters());
        String v = this.parameter.getV();
        //随机取值一个r
        Element r = pairing.getZr().newRandomElement().getImmutable();
        //赋值D  g B * g A r
        Element D = (masterSecretKeySerParameter.getgAlpha()).mul(masterSecretKeySerParameter.getGBeta().powZn(r)).getImmutable();
        //赋值L
        Element L = publicKeySerParameter.GetG().powZn(r).getImmutable();

        Map<String, Element> Dj = new HashMap<String, Element>();
        for (String attribute : attributes) {
            Element elementAttribute = PairingUtils.MapStringToGroup(pairing, attribute, PairingUtils.PairingGroupType.Zr);
            // j 在attribute中 ，tj在zp中
            // Element tj = pairing.getZr().newRandomElement().getImmutable();
            Element tj = pairing.getZr().newElementFromBytes(elementAttribute.toBytes()).getImmutable();

            Dj.put(attribute, publicKeySerParameter.GetG().powZn(tj).powZn(r).getImmutable());
        }
        Element vAttribute = PairingUtils.MapStringToGroup(pairing, v, PairingUtils.PairingGroupType.Zr);
        Element tv = pairing.getZr().newElementFromBytes(vAttribute.toBytes()).getImmutable();
        Map<String, Element> Dv = new HashMap<String, Element>();
        Dv.put(v, (publicKeySerParameter.GetG().powZn(tv)).powZn(r).getImmutable());
        //检查属性键的版本
        return new LSSSSecretKeySerParameter(publicKeySerParameter.getParameters(), D, L, Dj, Dv);
    }

    public boolean verifyVersion() {
        String v_set = this.verifyparameter.getV();
        String v = this.parameter.getV();
        if (!v.equals(v_set)) {
            return false;
        }
        return true;
    }
}
