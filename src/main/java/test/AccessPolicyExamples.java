package test;

import org.web3j.abi.datatypes.DynamicArray;
import org.web3j.abi.datatypes.Utf8String;

/**
 * Created by Weiran Liu on 2016/11/17.
 * <p>
 * Access policy examples, used for testing AccessControlEngine and Attribute-Based Encryption schemes.
 */
public class AccessPolicyExamples {

    //将版本号直接写入访问策略  将5直接写入访问策略， 在提取出来v的具体值

    public static final String access_policy_example_v1 = "60";//DO自己设置的
    public static final String access_policy_example_1 = "60 and 0 and 1 and (2 or 3)";//60 and 1 and 2 and (3 or 4)

    public static Utf8String v = new Utf8String("60");
    public static Utf8String s1 = new Utf8String("0");
    public static Utf8String s2 = new Utf8String("1");
    public static Utf8String s3 = new Utf8String("2");
    public static Utf8String s4 = new Utf8String("3");
    public static final DynamicArray<Utf8String> access_policy_attribute = new DynamicArray<Utf8String>(s1, s2, s3, s4);

//50 -26 58 42 17 91 -2 120 -53 100 51 124 21 -6 19 54 -94 -89 59 -29 -67 71 -85 118 109 -123 -9 -72 99 -81 72 8

    public static final String access_policy_example_v = "60";//DU输入的
    public static final String access_policy_example_v2 = "50";//DU输入的
    public static final String[] access_policy_example_1_satisfied_1 = new String[]{"0", "1", "2"};
    public static final String[] access_policy_example_1_satisfied_2 = new String[]{"0", "1", "2", "3"};
    public static final String[] access_policy_example_1_unsatisfied_1 = new String[]{"1", "2", "3"};

    public static final String access_policy_example_2 = "(60 and (0 and 1 and 2) and (3 or 4 or 5) and (6 and 7 and (8 or 9 or 10 or 11)))";
    public static final String[] access_policy_example_2_satisfied_1 = new String[]{"0", "1", "2", "4", "6", "7", "10"};
    public static final String[] access_policy_example_2_satisfied_2 = new String[]{"0", "1", "2", "5", "4", "6", "7", "8", "9", "10", "11"};
    public static final String[] access_policy_example_2_unsatisfied_1 = new String[]{"0", "1", "2", "6", "7", "10"};
    public static final String[] access_policy_example_2_unsatisfied_2 = new String[]{"0", "1", "2", "4", "6", "10"};
    public static final String[] access_policy_example_2_unsatisfied_3 = new String[]{"0", "1", "2", "3", "6", "7"};

    public static final String access_policy_example_3 =
            "60 and 00 and 01 and 02 and 03 and 04 and 05 and 06 and 07 and 08 and 09 and " +
                    "10 and 11 and 12 and 13 and 14 and 15 and 16 and 17 and 18 and 19 and " +
                    "20 and 21 and 22 and 23 and 24 and 25 and 26 and 27 and 28 and 29 and " +
                    "30 and 31 and 32 and 33 and 34 and 35 and 36 and 37 and 38 and 39 and " +
                    "40 and 41 and 42 and 43 and 44 and 45 and 46 and 47 and 48 and 49";
    public static final String[] access_policy_example_3_satisfied_1 = new String[]{
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
    };
    public static final String[] access_policy_example_3_unsatisfied_1 = new String[]{
            "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
            "40", "41", "42", "43", "44", "45", "46", "47", "48",
    };
    public static final String[] access_policy_example_3_unsatisfied_2 = new String[]{
            "04", "05", "06", "07", "08", "09",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31", "32", "33", "34", "37", "38", "39",
            "40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
    };

    //改变策略1            public static final String access_policy_example_1 = "60 and 0 and 1 and (2 or 3)";
    public static final String access_policy_example_4 = "60 and 0 and (1 or 5) and (2 or (1 and 4))";//访问策略是没有办法简化的
    public static final String[] access_policy_example_4_satisfied_1 = new String[]{"0", "1", "2"};
    public static final String[] access_policy_example_4_satisfied_2 = new String[]{"0", "1"};
    public static final String[] access_policy_example_4_satisfied_3 = new String[]{"0", "1", "4"};
    public static final String[] access_policy_example_4_satisfied_4 = new String[]{"0", "1", "2", "4"};
    public static final String[] access_policy_example_4_unsatisfied_1 = new String[]{"1", "2", "3"};

}
