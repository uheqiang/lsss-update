package cpabe.utils;

import org.bouncycastle.crypto.CipherParameters;

/**
 * @program: lsss
 * @description: 对于加密的接口类
 * @author: YST
 * @create: 2020-05-27
 **/
public interface PairingEncriptionGenerator {
    void init(CipherParameters params);
    PairingCipherSerParameter generateCiphertext();
}
