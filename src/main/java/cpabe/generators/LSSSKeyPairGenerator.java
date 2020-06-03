package cpabe.generators;

import cpabe.genparams.CPABEKeyPairGenerationParameter;
import cpabe.serparams.LSSSMasterSecretKeySerParameter;
import cpabe.serparams.LSSSPublicKeySerParameter;
import cpabe.utils.PairingKeyPairGenerator;
import cpabe.utils.PairingKeySerPair;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @program: lsss
 * @description: lsss的pair生成 生成publickey和master
 * @author: YST
 * @create: 2020-05-26
 **/
public class LSSSKeyPairGenerator implements PairingKeyPairGenerator {
    private CPABEKeyPairGenerationParameter parameters;

    public void init(KeyGenerationParameters keyGenerationParameter) {
        this.parameters = (CPABEKeyPairGenerationParameter) keyGenerationParameter;
    }

    public PairingKeySerPair generateKeyPair() {
        Pairing pairing = PairingFactory.getPairing(this.parameters.getPairingParameters());

        Element alpha = pairing.getZr().newRandomElement().getImmutable();//A
        Element beta = pairing.getZr().newRandomElement().getImmutable();//B
        Element g = pairing.getG1().newRandomElement().getImmutable();//g
        Element gAlpha = g.powZn(alpha).getImmutable();//g A
        Element h = g.powZn(beta).getImmutable();//g B
        Element f = g.powZn(beta.invert()).getImmutable();//转置
        Element eggAlpha = pairing.pairing(g, g).powZn(alpha).getImmutable();//e(g,g) A


        return new PairingKeySerPair(
                new LSSSPublicKeySerParameter(this.parameters.getPairingParameters(), g, h, eggAlpha, f, beta),
                new LSSSMasterSecretKeySerParameter(this.parameters.getPairingParameters(), gAlpha, alpha, h));

    }
}
