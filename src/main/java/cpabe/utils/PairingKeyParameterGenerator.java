package cpabe.utils;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

/**
 * @program: lsss
 * @description: 生成私钥的方法
 * @author: YST
 * @create: 2020-05-27
 **/
public interface PairingKeyParameterGenerator {
    void init(KeyGenerationParameters keyGenerationParameters, CipherParameters parameter);

    PairingKeySerParameter generateKey();
}
