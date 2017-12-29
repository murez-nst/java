package com.murez.branch.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import com.murez.branch.util.Math;

public class Rijndael {
    private ArrayList<int[][]> roundKeys;
    private int Nk, Nr;
    private final short[][] S_BOX = {
            { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 },
            { 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 },
            { 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 },
            { 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 },
            { 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 },
            { 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF },
            { 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 },
            { 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 },
            { 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 },
            { 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB },
            { 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 },
            { 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 },
            { 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A },
            { 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E },
            { 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF },
            { 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 }
    }, S_BOX_INVERSE = {
            { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB },
            { 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB },
            { 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E },
            { 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 },
            { 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 },
            { 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 },
            { 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 },
            { 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B },
            { 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 },
            { 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E },
            { 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B },
            { 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 },
            { 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F },
            { 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF },
            { 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D }
    };

    public Rijndael(String key) {
        int size;
        if((size = (key = Util.expand(key, null)).length()) > 32)
            throw new UnsupportedOperationException("Key is too long (inserted key: " + size + " bytes).");
        if(size <= 16) {
            Nk = 4;
            Nr = 10;
        }
        else if(size > 16 && size <= 24) {
            Nk = 6;
            Nr = 12;
        }
        else {
            Nk = 8;
            Nr = 14;
        }
        roundKeys = keySchedule(Util.fillBlock(key.toCharArray(), Nk));
    }

    public String encrypt(String message) {
        message = Util.expand(message, Util.PLAINTEXT_ID);
        int i, size = message.length(), left = size % (4 * Nk);
        size /= 4 * Nk;
        String cipher = "";
        ArrayList<int[][]> blocks = Util.fillBlock(message.toCharArray(), Nk, size);
        for(i = 0; i < size; i++)
            cipher += new String(Util.unBlocked(encrypt(blocks.get(i), roundKeys)));
        if(left > 0) {
            i = Nk;
            if(left <= 16)
                Nk = 4;
            else if(left > 16 && left <= 24)
                Nk = 6;
            else
                Nk = 8;
            int[][] state = Util.fillBlock(message.substring((size = message.length()) - left, size).toCharArray(), Nk);
            if(left / 4 != Nk)
                state[3][Nk - 1] = (4 * Nk) - left;
            cipher += new String(Util.unBlocked(encrypt(state, i == Nk? roundKeys : Util.slice(roundKeys, Nk))));
        }
        roundKeys = null; Nk = 0; Nr = 0;
        return cipher;
    }

    public String decrypt(String cipher) {
        int i, size = cipher.length(), left = size % (4 * Nk);
        size /= 4 * Nk;
        String message = "";
        ArrayList<int[][]> blocks = Util.fillBlock(cipher.toCharArray(), Nk, size);
        for(i = 0; i < size; i++)
            message += new String(Util.unBlocked(decrypt(blocks.get(i), roundKeys)));
        if(left > 0) {
            i = Nk;
            message += new String(Util.unBlocked(decrypt(Util.fillBlock(cipher.substring((size = cipher.length()) - left, size).toCharArray(), (Nk = left / 4)), i == Nk? roundKeys : Util.slice(roundKeys, Nk))));
        }
        if((i = message.charAt((size = message.length()) - 1)) < 16)
            message = new StringBuilder(message).delete(size - i, size).toString();
        message = Util.reform(message, Util.PLAINTEXT_ID);
        roundKeys = null; Nk = 0; Nr = 0;
        return message;
    }

    public void encrypt(File source, File target) {
        if(Util.hasBigCode(source))
            throw new java.nio.charset.UnsupportedCharsetException("Selected file has character with code > 0xff.");
        int i, left;
        long size;
        char[] c = new char[4 * Nk];
        try {
            size = source.length();
            left = (int) (size % (4 * Nk));
            size /= 4 * Nk;
            InputStreamReader reader = new InputStreamReader(new FileInputStream(source), Charset.forName("ISO-8859-1"));
            OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(target), Charset.forName("ISO-8859-1"));
            writer.write(left);
            for(i = 0; i < size; i++) {
                reader.read(c);
                writer.write(Util.unBlocked(encrypt(Util.fillBlock(c, Nk), roundKeys)));
            }
            if(left > 0) {
                i = Nk;
                if(left <= 16)
                    Nk = 4;
                else if(left > 16 && left <= 24)
                    Nk = 6;
                else
                    Nk = 8;
                reader.read((c = new char[4 * Nk]));
                writer.write(Util.unBlocked(encrypt(Util.fillBlock(c, Nk), i == Nk? roundKeys : Util.slice(roundKeys, Nk))));
            }
            reader.close();
            writer.close();
        } catch(IOException e) { e.printStackTrace(); }
        roundKeys = null; Nk = 0; Nr = 0;
    }

    public void decrypt(File source, File target) {
        char[] c = new char[4 * Nk];
        int i, left, N;
        long size;
        try {
            size = source.length() - 1;
            left = (int) (size % (4 * Nk));
            size /= 4 * Nk;
            InputStreamReader reader = new InputStreamReader(new FileInputStream(source), Charset.forName("ISO-8859-1"));
            if((N = reader.read()) > 0)
                if(left == 0) {
                    left = 4 * Nk;
                    size--;
                }
            OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(target), Charset.forName("ISO-8859-1"));
            for(i = 0; i < size; i++) {
                reader.read(c);
                writer.write(Util.unBlocked(decrypt(Util.fillBlock(c, Nk), roundKeys)));
            }
            if(N > 0) {
                i = Nk;
                reader.read((c = new char[left]));
                String lastMessage = new String(Util.unBlocked(decrypt(Util.fillBlock(c, (Nk = left / 4)), i == Nk? roundKeys : Util.slice(roundKeys, Nk))));
                writer.write(lastMessage.substring(0, N > (i = lastMessage.length())? i : N));
            }
            reader.close();
            writer.close();
        } catch(IOException e) { e.printStackTrace(); }
        roundKeys = null; Nk = 0; Nr = 0;
    }

    private int[][] encrypt(int[][] state, ArrayList<int[][]> expandedKey) {
        state = addRoundKey(state, expandedKey.get(0));
        for(int i = 1; i < Nr; i++)
            state = addRoundKey(mixColumns(shiftRows(subBytes(state, false), false), false), expandedKey.get(i));
        return addRoundKey(shiftRows(subBytes(state, false), false), expandedKey.get(Nr));
    }

    private int[][] decrypt(int[][] state, ArrayList<int[][]> expandedKey) {
        state = subBytes(shiftRows(addRoundKey(state, expandedKey.get(Nr)), true), true);
        for(int i = Nr - 1; i > 0; i--)
            state = subBytes(shiftRows(mixColumns(addRoundKey(state, expandedKey.get(i)), true), true), true);
        return addRoundKey(state, expandedKey.get(0));
    }

    private ArrayList<int[][]> keySchedule(int[][] key) {
        final int[] ROUND_COEFFICIENT = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6c, 0xd8, 0xab, 0x4d };
        int[][] block;
        int i, j, k;
        ArrayList<int[][]> roundKeys = new ArrayList<>();
        roundKeys.add(key);
        if(Nk < 8)
            for(i = 0; i < Nr; i++) {
                block = new int[4][Nk];
                block[0][0] = key[0][0] ^ subBytes(key[1][Nk - 1], false) ^ ROUND_COEFFICIENT[i];
                for(j = 1; j < 4; j++)
                    block[j][0] = key[j][0] ^ subBytes(key[(j + 1) % 4][Nk - 1], false);
                for(j = 1; j < Nk; j++)
                    for(k = 0; k < 4; k++)
                        block[k][j] = block[k][j - 1] ^ key[k][j];
                roundKeys.add(block);
                key = block;
            }
        else for(i = 0; i < Nr; i++) {
            block = new int[4][Nk];
            block[0][0] = key[0][0] ^ subBytes(key[1][7], false) ^ ROUND_COEFFICIENT[i];
            for(j = 1; j < 4; j++)
                block[j][0] = key[j][0] ^ subBytes(key[(j + 1) % 4][7], false);
            for(j = 1; j < 4; j++)
                for(k = 0; k < 4; k++)
                    block[k][j] = block[k][j - 1] ^ key[k][j];
            for(j = 0; j < 4; j++)
                block[j][4] = subBytes(block[j][3], false) ^ key[j][4];
            for(j = 5; j < 8; j++)
                for(k = 0; k < 4; k++)
                    block[k][j] = block[k][j - 1] ^ key[k][j];
            roundKeys.add(block);
            key = block;
        }
        return roundKeys;
    }

    private final int[][] mixColumns(int[][] state, boolean isInverse) {
        int[][] block = new int[4][Nk];
        int i, j;
        if(!isInverse)
            for(i = 0; i < Nk; i++)
                for(j = 0; j < 4; j++)
                    block[j][i] = Math.galoisFieldsMultiply(state[j][i], 2) ^ Math.galoisFieldsMultiply(state[(j + 1) % 4][i], 3) ^ state[(j + 2) % 4][i] ^ state[(j + 3) % 4][i];
        else for(i = 0; i < Nk; i++)
            for(j = 0; j < 4; j++)
                block[j][i] = Math.galoisFieldsMultiply(state[j][i], 14) ^ Math.galoisFieldsMultiply(state[(j + 1) % 4][i], 11) ^ Math.galoisFieldsMultiply(state[(j + 2) % 4][i], 13) ^ Math.galoisFieldsMultiply(state[(j + 3) % 4][i], 9);
        return block;
    }

    private final int[][] shiftRows(int[][] state, boolean isInverse) {
        int[][] block = new int[4][Nk];
        int i, j;
        if(!isInverse)
            if(Nk < 8)
                for(i = 0; i < Nk; i++)
                    for(j = 0; j < 4; j++)
                        block[j][i] = state[j][(i + j) % Nk];
            else for(i = 0; i < Nk; i++) {
                block[0][i] = state[0][i];
                block[1][i] = state[1][(i + 1) % 8];
                block[2][i] = state[2][(i + 3) % 8];
                block[3][i] = state[3][(i + 4) % 8];
            }
        else if(Nk < 8)
            for(i = Nk - 1; i > -1; i--)
                for(j = 0; j < 4; j++)
                    block[j][(i + j) % Nk] = state[j][i];
        else for(i = 0; i < Nk; i++) {
                block[0][i] = state[0][i];
                block[1][(i + 1) % Nk] = state[1][i];
                block[2][(i + 3) % Nk] = state[2][i];
                block[3][(i + 4) % Nk] = state[3][i];
            }
        return block;
    }

    private final int[][] subBytes(int[][] state, boolean isInverse) {
        int i, j;
        if(!isInverse)
            for(i = 0; i < Nk; i++)
                for(j = 0; j < 4; j++)
                    state[j][i] = subBytes(state[j][i], false);
        else for(i = 0; i < Nk; i++)
            for(j = 0; j < 4; j++)
                state[j][i] = subBytes(state[j][i], true);
        return state;
    }

    private final int subBytes(int value, boolean isInverse) {
        String hex;
        if((hex = Integer.toHexString(value)).length() == 1)
            hex = '0' + hex;
        if(isInverse)
            return S_BOX_INVERSE[Util.parseInt(hex.charAt(0))][Util.parseInt(hex.charAt(1))];
        return S_BOX[Util.parseInt(hex.charAt(0))][Util.parseInt(hex.charAt(1))];
    }

    private final int[][] addRoundKey(int[][] state, int[][] roundKey) {
        int i, j;
        for(i = 0; i < Nk; i++)
            for(j = 0; j < 4; j++)
                state[j][i] ^= roundKey[j][i];
        return state;
    }

    public String toString() {
        switch(Nk) {
            case 4: return "AES-128";
            case 6: return "AES-192";
            case 8: return "AES-256";
            default: return "Advanced Encryption Standard";
        }
    }

    private static class Util {
        private static final char[] PLAINTEXT_ID = { 1 };

        private final static ArrayList<int[][]> slice(ArrayList<int[][]> keySchedule, int Nb) {
            int i, size = keySchedule.size(), Nk = size - 7, N = 4;
            if(Nk == 8) {
                if(Nb == 4) N = 7;
                else N = 3;
            }
            for(i = 0; i < N; i++)
                keySchedule.remove(keySchedule.size() - 1);
            return fillBlock(unBlocked(keySchedule), Nb, size);
        }

        private final static boolean hasBigCode(File f) {
            int i;
            try {
                InputStreamReader reader = new InputStreamReader(new FileInputStream(f), Charset.forName("ISO-8859-1"));
                while((i = reader.read()) > -1)
                    if(i > 0xFF) {
                        reader.close();
                        return true;
                    }
                reader.close();
            } catch(IOException e) { e.printStackTrace(); }
            return false;
        }

        private static String reform(String message, char[] ID) {
            String result = "", tmp;
            boolean match = false;
            int i, j;
            char c;
            for(i = 0; i < message.length(); i++) {
                if((c = message.charAt(i)) == ID[0]) {
                    match = true;
                    if(ID.length > 1)
                        for(j = 1; j < ID.length; j++)
                            if(message.charAt(i + j) != ID[j]) {
                                match = false;
                                break;
                            }
                }
                if(match) {
                    tmp = Math.toBinaryString(BigInteger.valueOf(message.charAt(i + ID.length + 1)));
                    while(tmp.length() < 8)
                        tmp = '0' + tmp;
                    c = (char) Math.toInteger(Math.toBinaryString(BigInteger.valueOf(message.charAt(i + ID.length))) + tmp).intValue();
                    i += ID.length + 1;
                    match = !match;
                }
                result += c;
            }
            return result;
        }

        private static String expand(String message, char[] ID) {
            String expandedMessage = "", hex, tmp;
            int i, j;
            char c;
            for(i = 0; i < message.length(); i++)
                if((c = message.charAt(i)) <= 0xFF)
                    expandedMessage += c;
                else if(c > 0xFF && c <= 0xFFFF) {
                    if(ID != null)
                        for(j = 0; j < ID.length; j++)
                            expandedMessage += ID[j];
                    if((hex = Integer.toHexString(c)).length() < 4)
                        hex = '0' + hex;
                    for(j = 0; j < 4; j += 2) {
                        tmp = Math.toBinaryString(BigInteger.valueOf(Util.parseInt(hex.charAt(j + 1))));
                        while(tmp.length() < 4)
                            tmp = '0' + tmp;
                        expandedMessage += (char) Math.toInteger(Math.toBinaryString(BigInteger.valueOf(Util.parseInt(hex.charAt(j)))) + tmp).intValue();
                    }
                }
            return expandedMessage;
        }

        private final static char[] unBlocked(ArrayList<int[][]> blocks) {
            int i, j, k, n = 0, Nb = blocks.get(0)[0].length;
            char[] chars = new char[4 * Nb * blocks.size()];
            int[][] block;
            for(i = 0; i < blocks.size(); i++) {
                block = blocks.get(i);
                for(j = 0; j < Nb; j++)
                    for(k = 0; k < 4; k++, n++)
                        chars[n] = (char) block[k][j];
            }
            return chars;
        }

        private final static char[] unBlocked(int[][] block) {
            int i, j, n = 0, Nb = block[0].length;
            char[] chars = new char[4 * Nb];
            for(i = 0; i < Nb; i++)
                for(j = 0; j < 4; j++, n++)
                    chars[n] = (char) block[j][i];
            return chars;
        }

        private final static ArrayList<int[][]> fillBlock(char[] chars, int Nb, int size) {
            ArrayList<int[][]> blocks = new ArrayList<>();
            int i, j, k, n = 0;
            int[][] block;
            for(i = 0; i < size; i++) {
                block = new int[4][Nb];
                for(j = 0; j < Nb; j++)
                    for(k = 0; k < 4; k++, n++)
                        block[k][j] = chars[n];
                blocks.add(block);
            }
            return blocks;
        }

        private final static int[][] fillBlock(char[] chars, int Nb) {
            int[][] block = new int[4][Nb];
            int i = 0, j = -1;
            for(; i < chars.length; i++) {
                if(i % 4 == 0)
                    j++;
                block[i % 4][j] = chars[i];
            }
            return block;
        }

        private final static int parseInt(char hex) {
            switch(hex) {
                case 'A': case 'a': return 10;
                case 'B': case 'b': return 11;
                case 'C': case 'c': return 12;
                case 'D': case 'd': return 13;
                case 'E': case 'e': return 14;
                case 'F': case 'f': return 15;
                default: return Integer.parseInt(String.valueOf(hex));
            }
        }
    }
}