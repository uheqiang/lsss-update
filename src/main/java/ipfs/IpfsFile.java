package ipfs;

import io.ipfs.api.IPFS;
import io.ipfs.api.MerkleNode;
import io.ipfs.api.NamedStreamable;
import io.ipfs.multihash.Multihash;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * @program: lsss
 * @description: 和ipfs交互的代码增加文件删除文件
 * @author: YST
 * @create: 2020-06-08
 **/
public class IpfsFile {
    //添加文件，返回文件的哈希值
    public static String add(byte[] data) throws IOException {
        //ipfs 的网关
        IPFS ipfsfile = new IPFS("/ip4/127.0.0.1/tcp/5001");
        NamedStreamable.ByteArrayWrapper file = new NamedStreamable.ByteArrayWrapper(data);
        MerkleNode hash = ipfsfile.add(file).get(0);
        return hash.hash.toString();
    }

    //得到文件的具体内容
    public static byte[] get(String hash) throws IOException {
        IPFS ipfs = new IPFS("/ip4/127.0.0.1/tcp/5001");
        MerkleNode md = new MerkleNode(hash);
        byte[] data = ipfs.cat(md.hash);
        return data;
    }

    public static String upload(String filePathName) throws IOException {
        //filePathName指的是文件的上传路径+文件名，如D:/1.png  
        IPFS ipfsfile = new IPFS("/ip4/127.0.0.1/tcp/5001");
        NamedStreamable.FileWrapper file = new NamedStreamable.FileWrapper(new File(filePathName));
        MerkleNode addResult = ipfsfile.add(file).get(0);
        return addResult.hash.toString();
    }

    public static void download(String filePathName, String hash) throws IOException {
        IPFS ipfsfile = new IPFS("/ip4/127.0.0.1/tcp/5001");
        Multihash filePointer = Multihash.fromBase58(hash);
        byte[] data = ipfsfile.cat(filePointer);
        if (data != null) {
            File file = new File(filePathName);
            if (file.exists()) {
                file.delete();
            }
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data, 0, data.length);
            fos.flush();
            fos.close();
        }
    }
}