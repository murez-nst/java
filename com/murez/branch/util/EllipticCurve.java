package com.murez.branch.util;

import java.math.BigInteger;
import com.murez.branch.crypto.ECElGamal;

public class EllipticCurve {
    private BigInteger A, B, Fp;

    public EllipticCurve(BigInteger A, BigInteger B, BigInteger Fp) {
        if(BigInteger.valueOf(4).multiply(A.pow(3)).add(BigInteger.valueOf(27).multiply(B.pow(2))).mod(Fp).equals(BigInteger.ZERO))
            throw new ArithmeticException("Value of A or B element of Fp is not satisfied.");
        this.A = A;
        this.B = B;
        this.Fp = Fp;
    }

    public static EllipticCurve generate(int securityLevel) {
        int A, B, p, min_point = 999999, max_bit;
        switch(securityLevel) {
            case ECElGamal.LEVEL_CHEAP:
                max_bit = 134; break;
            case ECElGamal.LEVEL_LOW:
                max_bit = 320; break;
            case ECElGamal.LEVEL_NORMAL:
                max_bit = 448; break;
            case ECElGamal.LEVEL_HIGH:
                max_bit = 704; break;
            case ECElGamal.LEVEL_TOP_SECRET:
                max_bit = 1280; break;
            case ECElGamal.LEVEL_AMAZING:
                max_bit = 2560; break;
            default: throw new UnsupportedOperationException("Get security level from ECElGamal's static field.");
        }
        while((p = new java.util.Random().nextInt(max_bit)) < securityLevel);
        while((A = new java.util.Random().nextInt()) < min_point);
        while((B = new java.util.Random().nextInt()) < min_point);
        return new EllipticCurve(BigInteger.valueOf(A), BigInteger.valueOf(B), Math.getProbablePrime(p));
    }

    public BigInteger getA() {
        return A;
    }

    public BigInteger getB() {
        return B;
    }

    public BigInteger getField() {
        return Fp;
    }

    public String toString() {
        return "A = " + A + ", B = " + B + ", Fp = " + Fp;
    }
}
/*
public ECPoint[] getAllPoints() {
	java.util.ArrayList<ECPoint> points = new java.util.ArrayList<>();
	points.add(ECPoint.O);
	BigInteger x = BigInteger.ONE, y, exponent = Fp.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
	for(; x.compareTo(Fp) < 0; x = x.add(BigInteger.ONE))
		if(!(y = x.pow(3).add(A.multiply(x)).add(B).mod(Fp)).equals(BigInteger.ZERO))
			if(Math.squareModulo(new Jacobi(y, Fp)).equals(Jacobi.ONE)) {
				points.add(new ECPoint(x, Math.fastPow(y, exponent, Fp)));
				points.add(new ECPoint(x, Math.fastPow(y.negate(), exponent, Fp)));
			}
	ECPoint[] P = new ECPoint[points.size()];
	return points.toArray(P);
}*/