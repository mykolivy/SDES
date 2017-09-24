package cryptography;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.nio.charset.CharsetDecoder;

public class SDES {
    private final int KEY_LENGTH = 10;
    private final static int[][] S0 = new int[][] {
        {1,0,3,2},
        {3,2,1,0},
        {0,2,1,3},
        {3,1,3,1}
    };

    private final static int[][] S1 = new int[][] {
        {1,1,2,3},
        {2,0,1,3},
        {3,0,1,0},
        {2,1,0,3}
    };

    public static byte[] encrypt(byte[] msg, int key){
        int[] keys = getKeys(key);
        byte[] result = new byte[msg.length];
        for (int i = 0; i < result.length; i++)
            result[i] = encrypt(msg[i], keys);

        return result;
    }

    public static byte[] decrypt(byte[] msg, int key){
        int[] keys = getKeys(key);
        byte[] result = new byte[msg.length];
        for (int i = 0; i < result.length; i++)
            result[i] = decrypt(msg[i], keys);

        return result;
    }

    static byte encrypt(byte c, int[] keys)
    {
        int result = f(IP(c), keys[0]);
        result = (result << 28) >>> 24 | (result >>> 4);
        result = f(result, keys[1]);
        return (byte) inverseIP(result);
    }

    static byte decrypt(byte c, int[] keys)
    {
        int[] newKeys = new int[2];
        newKeys[0] = keys[1];
        newKeys[1] = keys[0];
        return encrypt(c, newKeys);
    }

    static int f(int plainText, int subKey){
        int L = plainText >>> 4;
        int R = plainText << 28 >>> 28;
        return (L^F(R, subKey)) << 4 | R;
    }

    static int P10(int key){
        return permutate(key, 4,2,1,9,0,6,3,8,5,7);
    }

    static int LS(int key) {
        return permutate(key, 4,0,1,2,3,9,5,6,7,8);
    }

    static int P8(int key) {
        return permutate(key, 1, 0, 5, 2, 6, 3, 7, 4);
    }

    static int[] getKeys(int key) {
        int[] result = new int[2];
        int shifted = LS(P10(key));
        result[0] = P8(shifted);
        shifted = LS(shifted);
        result[1] = P8(shifted);
        return result;
    }

    static int IP(int plainText) {
        //2 6 3 1 4 8 5 7
        return permutate(plainText, 1,3,0,4,7,5,2,6);
    }

    static int inverseIP(int cryptoText) {
        //4 1 3 5 7 2 8 6
        return permutate(cryptoText, 2, 0, 6, 1, 3, 5, 7, 4);
    }

    static int permutate(int bits, int... pos) {
        int permutatedBits = 0;
        for(int i = 0; i < pos.length; i++){
            permutatedBits |= (bits & (1 << pos[i])) >> pos[i] << i;
        }
        return permutatedBits;
    }

    static int F(int plainText, int subKey) {
        //4 1 2 3 2 3 4 1
        int permutation = permutate(plainText, 3,0,1,2,1,2,3,0);
        permutation ^= subKey;

        int substituted = 0;
        int i = ((permutation & (1 << 7)) >>> 6) | (permutation & (1 << 4)) >>> 4;
        int j = ((permutation & (1 << 6)) >>> 5) | (permutation & (1 << 5)) >>> 5;
        substituted |= S0[i][j] << 2;
        i = ((permutation & (1 << 3)) >>> 2) | (permutation & 1);
        j = ((permutation & (1 << 2)) >>> 1) | (permutation & (1 << 1)) >>> 1;
        substituted |= S1[i][j];

        // 2 4 3 1
        return permutate(substituted, 3,1,0,2);
    }
}