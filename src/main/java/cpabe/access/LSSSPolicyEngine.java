package cpabe.access;

import Jama.Matrix;
import cpabe.utils.BinaryTreeNode;
import cpabe.utils.PairingUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;

/**
 * Created by Weiran Liu on 2016/7/21.
 * <p>
 * LSSSPolicyEngine class that implements AccessControlEngine.
 * Since the implementations of function secretSharing, reconstructOmegas are the same in LSSS realization,
 * I create this abstract engine to cover all the same codes.
 */
public class LSSSPolicyEngine implements AccessControlEngine {
    public static final String SCHEME_NAME = "LSSS";

    private static LSSSPolicyEngine instance = new LSSSPolicyEngine();

    public static LSSSPolicyEngine getInstance() {
        return instance;
    }

    public String getEngineName() {
        return SCHEME_NAME;
    }

    public boolean isSupportThresholdGate() {
        return false;
    }


    //生成矩阵
    public AccessControlParameter generateAccessControl(int[][] accessPolicy, String[] rhos) {
        //init access tree
        AccessTreeNode rootAccessTreeNode = AccessTreeNode.GenerateAccessTree(accessPolicy, rhos);
        //reconstruct binary tree node
        BinaryTreeNode rootBinaryTreeNode = BinaryTreeNode.ReconstructBinaryTreeNode(accessPolicy, rhos);

        //generate lsss matrix
        Map<String, LinkedList<LinkedList<Integer>>> map = new LinkedHashMap<String, LinkedList<LinkedList<Integer>>>();
        int maxLen = 0;
        int rows = 0;
        //We maintain a global counter variable c, which is initialized to 1.
        int c = 1;
        LinkedList<Integer> vector = new LinkedList<Integer>();
        //We begin by labeling the root node of the tree with the vector (1) (a vector of length 1).
        vector.add(1);
        rootBinaryTreeNode.setVector(vector);

        LinkedList<BinaryTreeNode> queue = new LinkedList<BinaryTreeNode>();
        queue.add(rootBinaryTreeNode);

        while (!queue.isEmpty()) {
            BinaryTreeNode p = queue.removeFirst();
            if (p.getType() == BinaryTreeNode.NodeType.AND) {
                //If the parent node is and AND gate labeled by the vector v
                int size = p.getVector().size();
                LinkedList<Integer> pv = new LinkedList<Integer>();
                //we pad v with 0's at the end (if necessary) to make it of length c.
                if (size < c) {
                    pv.addAll(p.getVector());
                    for (int i = 0; i < c - size; i++) {
                        pv.add(0);
                    }
                } else {
                    pv.addAll(p.getVector());
                }
                //Then we label one of its children (right children) with the vector v|1
                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                lv.addAll(pv);
                lv.addLast(1);
                right.setVector(lv);
                queue.add(right);

                //Then we label one of its children (left children) with the vector (0,...,0)|-1
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                for (int i = 0; i < c; i++) {
                    rv.add(0);
                }
                rv.addLast(-1);
                left.setVector(rv);
                queue.add(left);
                //We now increment the value of c by 1.
                c += 1;
            } else if (p.getType() == BinaryTreeNode.NodeType.OR) {
                //If the parent node is an OR gate labeled by the vector v
                BinaryTreeNode left = p.getLeft();
                LinkedList<Integer> lv = new LinkedList<Integer>();
                //then we also label its (left) children by v (and the value of c stays the same)
                lv.addAll(p.getVector());
                left.setVector(lv);
                queue.add(left);

                BinaryTreeNode right = p.getRight();
                LinkedList<Integer> rv = new LinkedList<Integer>();
                //then we also label its (right) children by v (and the value of c stays the same)
                rv.addAll(p.getVector());
                right.setVector(rv);
                queue.add(right);
            } else {
                // leaf node
                rows += 1;
                int size = p.getVector().size();
                maxLen = size > maxLen ? size : maxLen;
                if (map.containsKey(p.getValue())) {
                    map.get(p.getValue()).add(p.getVector());
                } else {
                    LinkedList<LinkedList<Integer>> list = new LinkedList<LinkedList<Integer>>();
                    list.add(p.getVector());
                    map.put(p.getValue(), list);
                }
            }
        }

        for (Map.Entry<String, LinkedList<LinkedList<Integer>>> entry : map
                .entrySet()) {
            LinkedList<LinkedList<Integer>> v = entry.getValue();
            for (LinkedList<Integer> aV : v) {
                int size = aV.size();
                if (size < maxLen) {
                    for (int j = 0; j < maxLen - size; j++) {
                        aV.add(0);
                    }
                }
            }
        }

        //construct the lsss Matrix
        int[][] lsssMatrix = new int[rows][];
        String[] rhosParameter = new String[rhos.length];
        int i = 0;
        for (Map.Entry<String, LinkedList<LinkedList<Integer>>> entry : map.entrySet()) {
            LinkedList<LinkedList<Integer>> v = entry.getValue();
            for (LinkedList<Integer> aV : v) {
                rhosParameter[i] = entry.getKey();
                lsssMatrix[i] = new int[maxLen];
                for (int k = 0; k < maxLen; k++) {
                    lsssMatrix[i][k] = aV.get(k);
                }
                i += 1;
            }
        }
        return new LSSSPolicyParameter(rootAccessTreeNode, accessPolicy, lsssMatrix, rhosParameter);
    }

    //生成入i计算向量入i=Mi*v v中有需要共享的秘密值 v=(s,v1,v2,,,vn)
    public Map<String, Element> secretSharing(Pairing pairing, Element secret, AccessControlParameter accessControlParameter) {
        if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(accessControlParameter, LSSSPolicyParameter.class.getName());
        }
        LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter) accessControlParameter;
        int row = lsssPolicyParameter.getRow();//得到策略的行和列
        int column = lsssPolicyParameter.getColumn();
        //   System.out.println(row + " " + column);
        int[][] lsssMatrix = lsssPolicyParameter.getLSSSMatrix();
        Element[][] elementLSSSMatrix = new Element[row][column];
        for (int i = 0; i < lsssPolicyParameter.getRow(); i++) {
            for (int j = 0; j < lsssPolicyParameter.getColumn(); j++) {
                elementLSSSMatrix[i][j] = pairing.getZr().newElement(lsssMatrix[i][j]).getImmutable();
            }
        }
        //init vector v
        Element[] elementsV = new Element[column];
        elementsV[0] = secret.duplicate().getImmutable();
        for (int i = 1; i < elementsV.length; i++) {
            elementsV[i] = pairing.getZr().newRandomElement().getImmutable();
        }
        //secret share by matrix multiplication
        Map<String, Element> lambdaElementsMap = new HashMap<String, Element>();
        for (int i = 0; i < row; i++) {
            Element elementsLambda = pairing.getZr().newZeroElement().getImmutable();
            for (int j = 0; j < column; j++) {
                elementsLambda = elementsLambda.add(elementLSSSMatrix[i][j].mulZn(elementsV[j])).getImmutable();
            }
            //修改了键值的表示方式0-1 0-0 0-2 0-3
            // lambdaElementsMap.put(lsssPolicyParameter.getRhos()[i] + "-" + i, elementsLambda);
            lambdaElementsMap.put(lsssPolicyParameter.getRhos()[i], elementsLambda);
        }
        return lambdaElementsMap;
    }

    //生成wi
    public Map<String, Element> reconstructOmegas(Pairing pairing, String[] attributes, AccessControlParameter accessControlParameter) throws UnsatisfiedAccessControlException {
        if (!(accessControlParameter instanceof LSSSPolicyParameter)) {
            PairingUtils.NotVerifyCipherParameterInstance(accessControlParameter, LSSSPolicyParameter.class.getName());
        }
        LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter) accessControlParameter;
        int[] result;
      /*  String[] myatt = new String[30];
        int count = 0;
        for (String att : attributes) {
            for (String rho : lsssPolicyParameter.getRhos()) {
                if (rho.split("-")[0].equals(att)) {
                    myatt[count] = rho;
                    count++;
                }
            }
        }
        String[] att = Arrays.copyOf(myatt, count);//新产生的att*/
        //attributes
        String[] minSatisfiedAttributes = lsssPolicyParameter.minSatisfiedAttributeSet(attributes);
        String[] leafAttributes = lsssPolicyParameter.getRhos();//得到rho的值 带有后缀
        int[] rows = new int[minSatisfiedAttributes.length];//4
        int counter = 0;
        for (int i = 0; i < leafAttributes.length; i++) {
            //    System.out.println("leafAttributes" + leafAttributes[i]);
            for (String minSatisfiedAttribute : minSatisfiedAttributes) {
                //       System.out.println("minSatisfiedAttribute" + minSatisfiedAttribute);
                if (leafAttributes[i].equals(minSatisfiedAttribute)) {
                    //比较L矩阵和获得的S参数中各个元素，记下所有相同的元素对应的在数组中的位置，并生成一个新的矩阵，把相同的元素存在一个叫做result的数组之中，长度为counter
                    rows[counter++] = i;

                }
            }
        }
        result = new int[counter];
        System.arraycopy(rows, 0, result, 0, counter);
        //filter M to rows from all zero cols and transpose it
        //eliminate all zero cols
        counter = 0;
        int[] cols = new int[result.length];
        // System.out.println("------" + lsssPolicyParameter.getColumn());
        for (int j = 0; j < lsssPolicyParameter.getColumn(); j++) {
            for (int aResult : result) {
                if (lsssPolicyParameter.getLSSSMatrix()[aResult][j] != 0) {
                    if (counter == cols.length) {
                        //此时矩阵不满足解密的条件
                        throw new UnsatisfiedAccessControlException("Invalid access structure or attributes. Unable to reconstruct coefficients.");
                    }
                    //把不都为0的列数调出来，把列数j存到叫做的cols的数组之中,此时counter的含义是代表了新生成的M矩阵的列数
                    cols[counter++] = j;
                    break;
                }
            }
        }
        double[][] Mreduced = new double[counter][counter];
        for (int i = 0; i < result.length; i++) {
            for (int j = 0; j < result.length; j++) {
                //将原本M矩阵中的满足attributes条件的以及不都为0的列的条件的元素填到一个新的矩阵中，称为Mreduced，该矩阵事宜个长宽均为result.length的方阵
                Mreduced[j][i] = lsssPolicyParameter.getLSSSMatrix()[result[j]][cols[i]];
            }
        }
        //solve the linear system
        Matrix mA = new Matrix(Mreduced);
        mA = mA.inverse();
        double[] _b = get_identity_vector(mA.getColumnDimension());
        Matrix mb = new Matrix(_b, 1);
        Matrix res = mb.times(mA);
        double[] solution = res.getRowPackedCopy();

        Element[] minSatisfiedOmegaElements = new Element[solution.length];
        for (int i = 0; i < minSatisfiedOmegaElements.length; i++) {
            minSatisfiedOmegaElements[i] = pairing.getZr().newElement((int) solution[i]).getImmutable();
        }

        Map<String, Element> omegaElementsMap = new HashMap<String, Element>();
        for (int i = 0; i < rows.length; i++) {
            for (String attribute : attributes) {
                if (leafAttributes[rows[i]].equals(attribute)) {
                    omegaElementsMap.put(attribute, minSatisfiedOmegaElements[i].duplicate().getImmutable());
                }
            }
        }
        for (String attribute : attributes) {
            if (!omegaElementsMap.containsKey(attribute)) {
                omegaElementsMap.put(attribute, pairing.getZr().newZeroElement().getImmutable());
            }
        }
        return omegaElementsMap;
    }

    private double[] get_identity_vector(int length) {
        //该方法实现的功能是：生成矩阵求逆时等号右边的列向量，第一个数为1，剩下的都是0
        double[] result = new double[length];
        result[0] = 1.0;
        for (int i = 1; i < length; i++) {
            result[i] = 0.0;
        }
        return result;
    }
}
