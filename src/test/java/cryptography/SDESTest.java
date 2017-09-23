package cryptography;
import org.junit.Test;

import static org.junit.Assert.*;

public class SDESTest {
    SDES sdes = new SDES();

    @Test public void P10() {
        int key = 0b1010000010;
        int result = 0b1000001100;

        assertEquals("Wrong permutation", result, SDES.P10(key));
    }

    @Test public void LS(){
        int key = 0b1000001100;
        int result = 0b0000111000;

        assertEquals("Invalid permutation", result, SDES.LS(key));
    }

    @Test public void P8(){
        int key = 0b0000111000;
        int result = 0b10100100;

        assertEquals("Invalid permutation", result, SDES.P8(key));
    }

    @Test public void IP(){
        int plainText = 0b11110011;
        int result = 0b10111101;

        assertEquals("Invalid permutation", result, SDES.IP(plainText));
    }

    @Test public void inverseIP(){
        int plainText = 0b10111101;
        int result = 0b11110011;

        assertEquals("Invalid permutation", result, SDES.inverseIP(plainText));
    }

    @Test public void F(){
        int plainText = 0b0101;
        int subKey = 0b11100100;
        int result = 0b1001;

        assertEquals(result, SDES.F(plainText, subKey));
    }

    @Test public void getKeys(){
        int key = 0b1010000010;
        int[] result = new int[] {0b10100100, 0b10010010};

        assertArrayEquals(result, SDES.getKeys(key));
    }

    @Test public void encrypt(){
        byte msg = 0b00010111;
        int[] keys = new int[] {0b10100100, 0b10010010};

        assertEquals(0b00011010, SDES.encrypt(msg, keys));
    }

    @Test public void decrypt(){
        byte cryptoText = 0b00011010;
        byte result = 0b00010111;
        int[] keys = new int[] {0b10100100, 0b10010010};

        assertEquals(result, SDES.decrypt(cryptoText, keys));
    }

    @Test public void encryptAndDecryptSymmetry() {
        int[] keys = new int[] {0b10100100, 0b10010010};
        byte text = 0b01110110;

        assertEquals(text, SDES.decrypt(SDES.encrypt(text, keys), keys));
    }
}
