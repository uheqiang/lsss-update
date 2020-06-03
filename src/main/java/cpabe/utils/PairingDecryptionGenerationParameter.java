package cpabe.utils;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Created by Weiran Liu on 2016/11/20.
 *
 * Pairing decryption generation parameter
 */
public abstract class PairingDecryptionGenerationParameter implements CipherParameters {
    private PairingKeySerParameter publicKeyParameter;//PK
    private PairingKeySerParameter secretKeyParameter;//SK
    private PairingCipherSerParameter ciphertextParameter;//CT wi

    public PairingDecryptionGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter secretKeyParameter,
            PairingCipherSerParameter ciphertextParameter) {
        this.publicKeyParameter = publicKeyParameter;
        this.secretKeyParameter = secretKeyParameter;
        this.ciphertextParameter = ciphertextParameter;
    }
    public PairingKeySerParameter getPublicKeyParameter() { return this.publicKeyParameter; }

    public PairingKeySerParameter getSecretKeyParameter() { return this.secretKeyParameter; }

    public PairingCipherSerParameter getCiphertextParameter() { return this.ciphertextParameter; }
}
