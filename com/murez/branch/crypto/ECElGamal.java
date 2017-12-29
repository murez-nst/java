package com.murez.branch.crypto;

import java.math.BigInteger;
import com.murez.branch.util.ECPoint;
import com.murez.branch.util.EllipticCurve;

public class ECElGamal {
    public static final int LEVEL_CHEAP = 128, LEVEL_LOW = 256, LEVEL_NORMAL = 384, LEVEL_HIGH = 512, LEVEL_TOP_SECRET = 960, LEVEL_AMAZING = 2048;
    private EllipticCurve E;
    private ECPoint P;

    public ECElGamal(EllipticCurve ellipticCurve, ECPoint point) {
        E = ellipticCurve;
        P = point;
    }

    public String encrypt(String message, ECPoint publicKey) {
        message += message.length() % 2 == 1? (char) 0 : "";
        ECPoint[] M = new ECPoint[message.length() / 2];
        for(int i = 0, j = 0; i < message.length(); j++)
            M[j] = new ECPoint(BigInteger.valueOf(message.charAt(i++)), BigInteger.valueOf(message.charAt(i++)));
        return new com.murez.branch.util.Convert().toString(encrypt(M, publicKey));
    }

    public String decrypt(String cipher, BigInteger privateKey) {
        ECPoint[] M = decrypt(new com.murez.branch.util.Convert().toPoints(cipher), privateKey);
        String message = "";
        int i = 0;
        for(; i < M.length; i++)
            message += String.valueOf((char) M[i].getX().intValue()) + (char) M[i].getY().intValue();
        return message.charAt((i = message.length()) - 1) == 0? message.substring(0, i - 1) : message;
    }

    private ECPoint[][] encrypt(ECPoint[] M, ECPoint Q) {
        ECPoint[][] C = new ECPoint[M.length][2];
        long k;
        for(int i = 0; i < M.length; i++) {
            k = Math.abs(new java.util.Random().nextLong());
            C[i] = new ECPoint[] { P.sum(BigInteger.valueOf(k), E), M[i].sum(Q.sum(BigInteger.valueOf(k), E), E) };
        }
        return C;
    }

    private ECPoint[] decrypt(ECPoint[][] C, BigInteger n) {
        ECPoint[] M = new ECPoint[C.length];
        for(int i = 0; i < C.length; i++)
            M[i] = C[i][1].sub(C[i][0].sum(n, E), E);
        return M;
    }

    public String toString() {
        return "Elliptic curve equation: " + E + "\nSelected point: P = " + P;
    }
}