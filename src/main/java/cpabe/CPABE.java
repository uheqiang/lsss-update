package cpabe;

import cpabe.utils.*;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.PairingParameters;


/**
 * @program: lsss
 * @description: cp-abe的所有涉及的方法
 * @author: YST
 * @create: 2020-05-26
 **/
public abstract class CPABE {
    /*
    setup 函数
     * @param pairingParameters PairingParameters
     * @param maxAttributesNum maximal number of attributes supported, useless if no such limitation
     * @return public key / master secret key pair of the scheme
     */
    public abstract PairingKeySerPair setup(PairingParameters pairingParameters, int maxAttributesNum);

    /**
     * Secret Key Generation Algorithm for CP-ABE
     *
     * @param publicKey  public key
     * @param masterKey  master secret key
     * @param attributes associated attribute set
     * @return secret key associated with the attribute set
     */
    public abstract PairingKeySerParameter keyGen(PairingKeySerParameter publicKey, PairingKeySerParameter masterKey, String[] attributes, String v, String v_set);

    /**
     * Encryption Algorithm for CP-ABE
     *
     * @param publicKey    public key
     * @param accessPolicy associated access policy, given by string
     * @param message      the message in GT
     * @return ciphertext associated with the access policy
     * @throws PolicySyntaxException if error occurs when parsing the access policy string
     */
    public PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, String accessPolicy, Element message, String v) throws PolicySyntaxException {
        int[][] accessPolicyIntArrays = ParserUtils.GenerateAccessPolicy(accessPolicy);
        String[] rhos = ParserUtils.GenerateRhos(accessPolicy);
        return encryption(publicKey, accessPolicyIntArrays, rhos, message, v);
    }

    /**
     * Encryption Algorithm for CP-ABE
     *
     * @param publicKey             public key
     * @param accessPolicyIntArrays associated access policy, given by 2D int arrays
     * @param rhos                  associated rhos, given by string array
     * @param message               the message in GT
     * @return ciphertext associated with the access policy
     */
    public abstract PairingCipherSerParameter encryption(PairingKeySerParameter publicKey, int[][] accessPolicyIntArrays, String[] rhos, Element message, String v);

}
