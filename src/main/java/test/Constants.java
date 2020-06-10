package test;

import java.math.BigInteger;

/**
 * @program: lsss
 * @description: 所有的生成的常量
 * @author: YST
 * @create: 2020-06-08
 **/
public class Constants {
    // GAS价格
    public static BigInteger GAS_PRICE = BigInteger.valueOf(4700000L);
    // GAS上限
    public static BigInteger GAS_LIMIT = BigInteger.valueOf(3000000L);

    // 交易费用
    public static BigInteger GAS_VALUE = BigInteger.valueOf(100L);;
    // 账户密码
    public static String DO_PASSWORD = "do";
    // 账户文件路径
    public static String DO_PATH = "/root/ethereum/data/00/keystore/UTC--2020-06-03T10-06-58.246227657Z--2385c6eea84a248e8a043f363a637d26e0444128";

    // 账户密码
    public static String DU1_PASSWORD = "du";
    // 账户文件路径
    public static String DU1_PATH = "/root/ethereum/data/00/keystore/UTC--2020-06-03T10-07-38.372894030Z--bc485a956f82336a007f36c3c223c9d7331a0bef";

    // 账户密码
    public static String DU2_PASSWORD = "du1";
    // 账户文件路径
    public static String DU2_PATH = "/root/ethereum/data/00/keystore/UTC--2020-06-03T10-08-05.019561462Z--80c2a678a8a2faca62d1b29923ec8ebeef8a6178";

    // 账户密码
    public static String AC_PASSWORD = "ac";
    // 账户文件路径
    public static String AC_PATH = "/root/ethereum/data/00/keystore/UTC--2020-06-03T10-08-59.956135586Z--82cb0606ceca5d7beb99da893abe4de2c25d0be1";



    // 合约地址，第一次部署之后记录下来
    public static String ADDRESS = "0x61619391fe9c5ec758055b95d9e4786a54f29eb5";
    public static byte CHAINID = (byte) 19999; //chain id,在创世区块中定义的

}
