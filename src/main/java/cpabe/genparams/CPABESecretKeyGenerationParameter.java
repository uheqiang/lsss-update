package cpabe.genparams;

import cpabe.utils.PairingKeyGenerationParameter;
import cpabe.utils.PairingKeySerParameter;
import cpabe.utils.PairingUtils;

/**
 * @program: lsss
 * @description: cpabe 的secret key的生成
 * @author: YST
 * @create: 2020-05-27
 **/
public class CPABESecretKeyGenerationParameter extends PairingKeyGenerationParameter {
    private String[] attributes;
    private String v;

    //获取属性值赋值属性值 用户自己输入还有版本号
    public CPABESecretKeyGenerationParameter(
            PairingKeySerParameter publicKeyParameter, PairingKeySerParameter masterSecretKeyParameter, String[] attributes, String v) {
        super(publicKeyParameter, masterSecretKeyParameter);
        this.attributes = PairingUtils.removeDuplicates(attributes);
        this.v = v;
    }

    public String[] getAttributes() {
        return this.attributes;
    }

    public String getV() {
        return this.v;
    }
}
