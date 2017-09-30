package cryptography;

import org.junit.Test;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.*;
import java.util.*;

public class SDESTest {
    @Test public void P10() {
        int key = 0b1010000010;
        int result = 0b1000001100;

        assertEquals("Wrong permutation", result, cryptography.SDES.P10(key));
    }

    @Test public void LS(){
        int key = 0b1000001100;
        int result = 0b0000111000;

        assertEquals("Invalid permutation", result, cryptography.SDES.LS(key));
    }

    @Test public void P8(){
        int key = 0b0000111000;
        int result = 0b10100100;

        assertEquals("Invalid permutation", result, cryptography.SDES.P8(key));
    }

    @Test public void IP(){
        int plainText = 0b11110011;
        int result = 0b10111101;

        assertEquals("Invalid permutation", result, cryptography.SDES.IP(plainText));
    }

    @Test public void inverseIP(){
        int plainText = 0b10111101;
        int result = 0b11110011;

        assertEquals("Invalid permutation", result, cryptography.SDES.inverseIP(plainText));
    }

    @Test public void F(){
        int plainText = 0b0101;
        int subKey = 0b11100100;
        int result = 0b1001;

        assertEquals(result, cryptography.SDES.F(plainText, subKey));
    }

    @Test public void getKeys(){
        int key = 0b1010000010;
        int[] result = new int[] {0b10100100, 0b10010010};

        assertArrayEquals(result, cryptography.SDES.getKeys(key));
    }

    @Test public void encrypt(){
        byte msg = 0b00010111;
        int[] keys = new int[] {0b10100100, 0b10010010};
        int[] oldKeys = new int[] {0b10100100, 0b10010010};

        assertEquals(0b00011010, cryptography.SDES.encrypt(msg, keys));
        assertArrayEquals(oldKeys, keys);
    }

    @Test public void decrypt(){
        byte cryptoText = 0b00011010;
        byte result = 0b00010111;
        int[] keys = new int[] {0b10100100, 0b10010010};
        int[] oldKeys = new int[] {0b10100100, 0b10010010};

        assertEquals(result, cryptography.SDES.decrypt(cryptoText, keys));
        assertArrayEquals(oldKeys, keys);
    }

    @Test public void encryptAndDecryptSymmetry() {
        int[] keys = new int[] {0b10100100, 0b10010010};
        byte text = 0b1110011;
        int[] oldKeys = new int[] {0b10100100, 0b10010010};

        assertEquals(text, cryptography.SDES.decrypt(cryptography.SDES.encrypt(text, keys), keys));
        assertArrayEquals(oldKeys, keys);
    }

    @Test public void encryptAndDecryptStringSymmetry() {
        int key = 0b1010000010;
        String msg = "abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        assertEquals(msg, cryptography.SDES.decrypt(cryptography.SDES.encrypt(msg, key), key));
    }

    @Test public void encryptStream() throws IOException {
        int key = 0b0100011011;
        InputStream in = new ByteArrayInputStream(new byte[] {1,2,3});
        OutputStream out = mock(OutputStream.class);
        List<Integer> result = new LinkedList<>();
        doAnswer(invocation -> result.add(invocation.getArgument(0)))
                .when(out)
                .write(anyInt());

        cryptography.SDES.encrypt(in, out, key);

        assertEquals(Arrays.asList(147,218,88), result);
    }

    @Test public void decryptStream() throws IOException {
        int key = 0b0100011011;
        InputStream in = new ByteArrayInputStream(new byte[] {(byte)147,(byte)218,(byte)88});
        OutputStream out = mock(OutputStream.class);
        List<Integer> result = new LinkedList<>();
        doAnswer(invocation -> result.add(invocation.getArgument(0)))
                .when(out)
                .write(anyInt());

        cryptography.SDES.decrypt(in, out, key);

        assertEquals(Arrays.asList(1, 2, 3), result);
    }
}
