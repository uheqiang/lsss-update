package cpabe.serparams;

import cpabe.utils.PairingKeySerParameter;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.util.Arrays;

/**
 * @program: lsss
 * @description: 生成publickey
 * @author: YST
 * @create: 2020-05-26
 **/
public class LSSSPublicKeySerParameter extends PairingKeySerParameter {
    public transient Element g;
    private final byte[] byteArrayG;
    private transient Element eggAlpha;
    private final byte[] byteArrayEggAlpha;
    private transient Element h;
    private final byte[] byteArrayH;//
    private transient Element f;
    private final byte[] byteArrayF;//
    private transient Element b;
    private final byte[] byteArrayB;


    public LSSSPublicKeySerParameter(PairingParameters parameters, Element g, Element h, Element eggAlpha, Element f, Element b) {
        super(false, parameters);
        this.g = g.getImmutable();////使a的值不能通过点来改变，只可以通过赋值等号来改变
        this.byteArrayG = this.g.toBytes();
        this.eggAlpha = eggAlpha.getImmutable();
        this.byteArrayEggAlpha = this.eggAlpha.toBytes();
        this.h = h.getImmutable();
        this.byteArrayH = this.h.toBytes();
        this.f = f.getImmutable();
        this.byteArrayF = this.f.toBytes();
        this.b = b.getImmutable();
        this.byteArrayB = this.b.toBytes();
    }

    public Element GetG() {
        return this.g.duplicate();
    }

    public Element getEggAlpha() {
        return this.eggAlpha.duplicate();
    }

    public Element getH() {
        return this.h.duplicate();
    }

    public Element getF() {
        return this.f.duplicate();
    }

    public Element getB() {
        return this.b.duplicate();
    }


    @Override
    public boolean equals(Object anObject) {
        if (this == anObject) {
            return true;
        }
        if (anObject instanceof LSSSPublicKeySerParameter) {
            LSSSPublicKeySerParameter that = (LSSSPublicKeySerParameter) anObject;
            //Compare g
            if (!PairingUtils.isEqualElement(this.g, that.g)) {
                // System.out.println(1);
                return false;
            }
            if (!Arrays.equals(this.byteArrayG, that.byteArrayG)) {
                // System.out.println(2);
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.h, that.h)) {
                //   System.out.println(3);
                return false;
            }
            if (!Arrays.equals(this.byteArrayH, that.byteArrayH)) {
                //  System.out.println(4);
                return false;
            }
            //Compare eggAlpha
            if (!PairingUtils.isEqualElement(this.eggAlpha, that.eggAlpha)) {
                //  System.out.println(9);
                return false;
            }
            if (!Arrays.equals(this.byteArrayEggAlpha, that.byteArrayEggAlpha)) {
                //  System.out.println(10);
                return false;
            }
            //Compare h
            if (!PairingUtils.isEqualElement(this.f, that.f)) {
                //  System.out.println(5);
                return false;
            }
            if (!Arrays.equals(this.byteArrayF, that.byteArrayF)) {
                //  System.out.println(6);
                return false;
            }
            if (!PairingUtils.isEqualElement(this.b, that.b)) {
                //  System.out.println(7);
                return false;
            }
            if (!Arrays.equals(this.byteArrayB, that.byteArrayB)) {
                //  System.out.println(8);
                return false;
            }
            //Compare Pairing Parameters
            return this.getParameters().toString().equals(that.getParameters().toString());
        }
        return false;
    }
    /*
    现在jPBC可以使用的曲线为如下几类：

Type A Type A1 Type D Type E Type F Type G
现在密码学实现基本只使用Type A和Type A1的。前者为对称质数阶双线性群，后者为合数阶对称双线性群。
在jPBC中，双线性群的使用都是通过叫做Pairing的对象来实现的。双线性群的初始化在jPBC中就是对Pairing对象的初始化。双线性群有两种初始化的方法。第一种是通过代码动态产生一个双线性群，第二种是从文件中读取参数而产生群。

我们研究质数阶双线性群

     */
    /*
    产生质数双线性群中的随机数
    质数双线性群可以由五元组(p,G1,G2,GT,e)来描述。五元组中p是一个与给定安全常数λ相关的大质数，G1,G2,GT均是阶为p的乘法循环群，e为双线性映射e:G1×G2→GT，它满足以下3个条件：
    双线性（Bilinearity）：对于任意的g∈G1，h∈G2，a,b∈Zp，有e(ga,hb)=e(g,h)ab； 非退化性（Non-degeneracy）：至少存在元素g1∈G1,g2∈G2，满足e(g1,g2)≠1； 可计算性（Efficiency）：对于任意的u∈G1,v∈G2，存在一个与给定安全常数λ相关的多项式时间算法，可以高效地计算e(u,v)；
     */

    private void readObject(java.io.ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
        objectInputStream.defaultReadObject();
        // System.out.println("开始");
        Pairing pairing = PairingFactory.getPairing(getParameters());
        this.g = pairing.getG1().newElementFromBytes(this.byteArrayG).getImmutable();//G1
        this.h = pairing.getG1().newElementFromBytes(this.byteArrayH).getImmutable();//
        this.b = pairing.getZr().newElementFromBytes(this.byteArrayB).getImmutable();//B
        this.f = pairing.getG1().newElementFromBytes(this.byteArrayF).getImmutable();//G0 也就是运算
        this.eggAlpha = pairing.getGT().newElementFromBytes(this.byteArrayEggAlpha).getImmutable();//e(g,g)

    }
}
