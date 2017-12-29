package com.murez.branch.util;

import java.math.BigInteger;

public class ECPoint {
    public static final ECPoint O = new ECPoint();
    private BigInteger x, y;
    private boolean isInfinity;

    private ECPoint() {
        isInfinity = true;
    }

    public ECPoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

	/*public BigInteger nCyclic(EllipticCurve E) {
		BigInteger N = BigInteger.ONE, n = BigInteger.valueOf(2);
		while(!this.sum(n, E).equals(ECPoint.O)) {
			n = n.add(BigInteger.ONE);
			N = N.add(BigInteger.ONE);
		}
		return N;
	}*/

    public static ECPoint getRandPoint(EllipticCurve E) {
        ECPoint P = ECPoint.O;
        BigInteger x = BigInteger.ONE, y, p = E.getField(), exp = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
        for(; x.compareTo(p) < 0; x = x.add(BigInteger.ONE)) {
            if((y = x.pow(3).add(x.multiply(E.getA())).add(E.getB()).mod(p)).compareTo(BigInteger.ZERO) > 0)
                if(Math.squareModulo(new Legendre(y, p)).equals(Legendre.ONE)) {
                    P = new ECPoint(x, Math.fastPow(y, exp, p));
                    break;
                }
        }
        return P.sum(BigInteger.valueOf(new java.util.Random().nextInt()).abs(), E);
    }

    public ECPoint sum(ECPoint P, EllipticCurve E) {
        if(this.equals(O))
            return P;
        if(P.equals(O))
            return this;
        if(P.equals(negate(this)))
            return O;
        BigInteger slope = null, p = E.getField(), A = E.getA();
        try {
            if(this.equals(P))
                slope = x.pow(2).multiply(BigInteger.valueOf(3)).add(A).mod(p).multiply(y.multiply(BigInteger.valueOf(2)).modInverse(p)).mod(p);
            else
                slope = P.getY().subtract(y).mod(p).multiply(P.getX().subtract(x).modInverse(p)).mod(p);
        }
        catch(ArithmeticException e) { return O; }
        BigInteger X = slope.pow(2).subtract(x.add(P.getX())).mod(p);
        return new ECPoint(X, slope.multiply(x.subtract(X)).subtract(y).mod(p));
    }

    public ECPoint sum(BigInteger n, EllipticCurve E) {
        if(n.compareTo(BigInteger.ONE) < 1)
            throw new ArithmeticException("Choose n > 1");
        ECPoint P = this, Q = ECPoint.O;
        while(n.compareTo(BigInteger.ZERO) > 0) {
            if(n.mod(BigInteger.valueOf(2)).equals(BigInteger.ONE))
                Q = Q.sum(P, E);
            P = P.sum(P, E);
            n = n.divide(BigInteger.valueOf(2));
        }
        return Q;
    }

    public ECPoint sub(ECPoint P, EllipticCurve E) {
        return sum(new ECPoint(P.getX(), P.getY().negate()), E);
    }

    public static final ECPoint negate(ECPoint P) {
        return new ECPoint(P.getX(), P.getY().negate());
    }

    public BigInteger getX() {
        if(isInfinity)
            return null;
        return x;
    }

    public BigInteger getY() {
        if(isInfinity)
            return null;
        return y;
    }

    public String toString() {
        if(this.equals(O))
            return "Infinity";
        else return "(" + x + ", " + y + ")";
    }
}