package cpabe.utils;

import cpabe.access.UnsatisfiedAccessControlException;
import it.unisa.dia.gas.jpbc.Element;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;

public interface PairingDecryptionGenerator {
    void init(CipherParameters params);

    Element recoverMessage() throws InvalidCipherTextException, UnsatisfiedAccessControlException;
}
