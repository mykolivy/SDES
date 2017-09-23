import java.util.BitSet;

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

    public byte[] encrypt(byte[] msg, BitSet key){
        throw new UnsupportedOperationException();
    }

    public byte[] decrypt(byte[] msg, BitSet key){
        throw new UnsupportedOperationException();
    }

    public String encrypt(String msg, BitSet key){
        return new String(encrypt(msg.getBytes(), key));
    }

    public String decrypt(String msg, BitSet key){
        return new String(decrypt(msg.getBytes(), key));
    }


    BitSet P10(BitSet key){
        if(key.length() != 10)
            throw new IllegalArgumentException("P10 requires a 10-bit key, " + key.length() + " bits given");
        return permutate(key, 4,2,1,9,0,6,3,8,5,7);
    }

    BitSet LS(BitSet key) {
        return permutate(key, 4,0,1,2,3,9,5,6,7,8);
    }

    BitSet P8(BitSet key) {
        return permutate(key, 1, 0, 5, 2, 6, 3, 7, 4);
    }

    BitSet IP(BitSet plainText) {
        //2 6 3 1 4 8 5 7
        return permutate(plainText, 6, 2, 5, 7, 4, 0, 3, 1);
    }

    BitSet inverseIP(BitSet cryptoText) {
        //4 1 3 5 7 2 8 6
        return permutate(cryptoText, 2, 0, 6, 1, 3, 5, 7, 4);
    }

    BitSet permutate(BitSet bitSet, int... pos) {
        BitSet permutatedKey = new BitSet(pos.length);
        for(int i = 0; i < pos.length; i++){
            permutatedKey.set(i, bitSet.get(pos[i]));
        }
        return permutatedKey;
    }

    BitSet F(BitSet plainText, BitSet subKey) {
        if(plainText.length() != 4)
            throw new IllegalArgumentException("P10 requires a 10-bit key, " + plainText.length() + " bits given");

        //4 1 2 3 2 3 4 1
        BitSet permutation = permutate(plainText, 8,7,6,5,6,5,4,7);
        permutation.xor(subKey);

        BitSet substituted = new BitSet(4);
        int i1 = 0 || ;
        substituted.or(BitSet.valueOf(new long[]{S0[permutation.get]}));

    }
}