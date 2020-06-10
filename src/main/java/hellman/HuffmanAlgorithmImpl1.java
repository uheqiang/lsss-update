package hellman;

import java.util.ArrayList;

/**
 * @program: lsss
 * @description:
 * @author: YST
 * @create: 2020-06-10
 **/
public class HuffmanAlgorithmImpl1 extends HuffmanAlgorithmAbstract {

    /*
     * 创建哈夫曼树； 丢失了letterList中的数据，深拷贝letterList是需要完善的地方
     */
    @Override
    protected Node createTree(ArrayList<Node> letterList) {
        init(letterList);
        while (letterList.size() != 1) {
            int size = letterList.size();
            // 小的节点放在右边（眼睛看到的左边）
            Node nodeLeft = letterList.get(size - 1);
            Node nodeRight = letterList.get(size - 2);
            Node nodeParent = new Node();
            nodeParent.setLeftChild(nodeLeft);
            nodeParent.setRightChild(nodeRight);
            Data data = new Data();
            data.setFrequency(nodeRight.getData().getFrequency()
                    + nodeLeft.getData().getFrequency());
            nodeParent.setData(data);
            letterList.set(size - 2, nodeParent);
            letterList.remove(size - 1);
            sort(letterList);

        }
        Node rootNode = letterList.get(0);
        return rootNode;
    }

    /**
     * 初始化 让节点列表有序
     */
    private void init(ArrayList<Node> letterList) {
        sort(letterList);
    }

    /**
     * 冒泡排序，把小的放在最后
     */
    private void sort(ArrayList<Node> letterList) {
        int size = letterList.size();
        // 处理只有一个元素的情况，也就是说，不需要排序
        if (size == 1) {
            return;
        }
        for (int i = 0; i < size; i++) {
            for (int j = 0; j < size - 1 - i; j++) {
                if (letterList.get(j).getData().getFrequency() < letterList
                        .get(j + 1).getData().getFrequency()) {
                    Node tempNode = letterList.get(j);
                    letterList.set(j, letterList.get(j + 1));
                    letterList.set(j + 1, tempNode);

                }
            }
        }
    }

    /**
     * 二进制字符串转换为byte数组,每个字节以","隔开
     **/
    public byte[] conver2HexToByte(String hex2Str) {
        byte[] b = new byte[hex2Str.length() / 8 + 1];
        int count = 0;
        for (int i = 0; i < hex2Str.length(); i = i + 8) {
            String m = null;
            if (i + 8 > hex2Str.length()) {
                m = hex2Str.substring(i, hex2Str.length());
            } else {
                m = hex2Str.substring(i, i + 8);
            }
            byte result = 0;
            for (int k = m.length() - 1, j = 0; k >= 0; k--, j++) {
                result += (Byte.parseByte(m.charAt(k) + "") * Math.pow(2, j));
            }
            b[count] = result;
            count++;

        }
        return b;
    }

    //将字节数组的字符串转化成真正的字节数组
    public byte[] conver2StringToByte(String byte2Str) {
        String[] b = byte2Str.split(",");
        byte[] my = new byte[b.length];
        int count = 0;
        for (int i = 0; i < b.length; i++) {
            if (b[i].contains("[")) {
                b[i] = b[i].replace('[', ' ').trim();
            }
            if (b[i].contains("]")) {
                b[i] = b[i].replace(']', ' ').trim();
            }
            b[i] = b[i].trim();
            byte m = Integer.valueOf(b[i]).byteValue();
            my[count] = m;
            count++;
        }
        return my;
    }


}
