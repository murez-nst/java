package com.murez.branch.util;

import com.murez.branch.util.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;

public class Convert {
    private final char[]
            foldChars = { 'a', 'i', 'u', 'e', 'o', 'A', 'I', 'U', 'E', 'O' },
            extraChars = { 183, 167, 1000 },
            availableChars = new char[92];

    public Convert() {
        int i = 32, n = 0;
        for(; i <= 64; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 68; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 72; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 78; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 84; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 96; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 100; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 104; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 110; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 116; i++, n++)
            availableChars[n] = (char) i;
        for(i++; i <= 126; i++, n++)
            availableChars[n] = (char) i;
        availableChars[n] = (char) 163; n++;
        availableChars[n] = (char) 166; n++;
        availableChars[n] = (char) 193; n++;
        availableChars[n] = (char) 201; n++;
        availableChars[n] = (char) 205; n++;
        availableChars[n] = (char) 211; n++;
        availableChars[n] = (char) 223; n++;
    }

    public ECPoint toPoint(String cipher) {
        String[] singlePoint = slice(cipher, extraChars[0]), tmp = new String[3], P = new String[2];
        boolean b;
        char c;
        for(int i = 0, j; i < singlePoint.length; i++) {
            tmp[0] = toUnreadableCipher(singlePoint[i]);
            tmp[2] = "";
            b = false;
            for(j = 0; j < tmp[0].length(); j++) {
                if((c = tmp[0].charAt(j)) == extraChars[2]) {
                    b = !b;
                    break;
                }
                tmp[1] = String.valueOf((int) c);
                while(tmp[1].length() < 3)
                    tmp[1] = '0' + tmp[1];
                tmp[2] += tmp[1];
            }
            if(b) tmp[2] += tmp[0].substring(j + 1, tmp[0].length());
            P[i] = tmp[2];
        }
        return new ECPoint(new BigInteger(P[0]), new BigInteger(P[1]));
    }

    public ECPoint[][] toPoints(String cipher) {
        String[] points = slice(cipher, extraChars[1]), singlePoint, P = new String[4], tmp = new String[3];
        ECPoint[][] M = new ECPoint[points.length][2];
        boolean b;
        char c;
        for(int i = 0, j, k; i < points.length; i++) {
            singlePoint = slice(points[i], extraChars[0]);
            for(j = 0; j < 4; j++) {
                tmp[0] = toUnreadableCipher(singlePoint[j]);
                tmp[2] = "";
                b = false;
                for(k = 0; k < tmp[0].length(); k++) {
                    if((c = tmp[0].charAt(k)) == extraChars[2]) {
                        b = !b;
                        break;
                    }
                    tmp[1] = String.valueOf((int) c);
                    while(tmp[1].length() < 3)
                        tmp[1] = '0' + tmp[1];
                    tmp[2] += tmp[1];
                }
                if(b) tmp[2] += tmp[0].substring(k + 1, tmp[0].length());
                P[j] = tmp[2];
            }
            M[i][0] = new ECPoint(new BigInteger(P[0]), new BigInteger(P[1]));
            M[i][1] = new ECPoint(new BigInteger(P[2]), new BigInteger(P[3]));
        }
        return M;
    }

    public String toString(ECPoint[][] C) {
        ECPoint P;
        String cipher = "";
        for(int i = 0, j; i < C.length; i++) {
            for(j = 0; j < 2; j++) {
                P = C[i][j];
                cipher += slice(P.getX().toString()) + extraChars[0] + slice(P.getY().toString()) + extraChars[0];
            }
            cipher += extraChars[1];
        }
        return cipher;
    }

    public String toString(ECPoint P) {
        return slice(P.getX().toString()) + extraChars[0] + slice(P.getY().toString()) + extraChars[0];
    }

    public String toReadableCipher(String cipher) {
        String R = "";
        int i = 0, j;
        for(; i < cipher.length(); i++) {
            if((j = cipher.charAt(i)) >= availableChars.length) {
                R += foldChars[(j / availableChars.length) - 1];
                R += availableChars[j % availableChars.length];
            }
            else R += availableChars[j];
        }
        return R;
    }

    public String toUnreadableCipher(String cipher) {
        String R = "";
        int i = 0, j;
        for(; i < cipher.length(); i++) {
            if((j = get(cipher.charAt(i), availableChars)) < 0)
                j = get(cipher.charAt(i + 1), availableChars) + (availableChars.length * (get(cipher.charAt(i++), foldChars) + 1));
            R += (char) j;
        }
        return R;
    }

    private String[] slice(String longString, char separator) {
        java.util.ArrayList<String> R = new ArrayList<>();
        for(int i = 0, j = 0; i < longString.length(); i++)
            if(longString.charAt(i) == separator) {
                R.add(longString.substring(j, i));
                j = i + 1;
            }
        String[] newStrings = new String[R.size()];
        return R.toArray(newStrings);
    }

    private String slice(String longString) {
        int i, j = 0, size = longString.length();
        String left, R = "";
        for(i = 0; i < size / 3; i++)
            R += (char) Integer.parseInt(String.valueOf(longString.charAt(j++)) + longString.charAt(j++) + longString.charAt(j++));
        if((left = longString.substring(j, size)).length() > 0)
            R += String.valueOf(extraChars[2]) + left;
        return toReadableCipher(R);
    }

    private int get(char target, char[] source) {
        for(int i = 0; i < source.length; i++)
            if(target == source[i])
                return i;
        return -1;
    }

    public char[] getAvailableChars() {
        return availableChars;
    }

    public char[] getFoldChars() {
        return foldChars;
    }
}