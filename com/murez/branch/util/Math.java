package com.murez.branch.util;

import java.math.BigInteger;

public class Math {
    private final static BigInteger TWO = BigInteger.valueOf(2);

    public static BigInteger getProbablePrime(int bitLength) {
        return BigInteger.probablePrime(bitLength, new java.util.Random());
    }

    public final static BigInteger toInteger(String binaryString) {
        binaryString = binaryString.toUpperCase();
        int n = binaryString.length(), i = 0;
        for(; i < n; i++)
            if(binaryString.charAt(i) != '1' && binaryString.charAt(i) != '0')
                throw new UnsupportedOperationException("Input is not binary string.");
        BigInteger result = BigInteger.ZERO;
        for(i = 0; i < n; i++)
            if(binaryString.charAt(i) == '1')
                result = result.add(TWO.pow(n - (i + 1)));
        return result;
    }

    public final static String toBinaryString(BigInteger n) {
        if(n.compareTo(BigInteger.ZERO) < 0)
            throw new UnsupportedOperationException("Only deal with number is positive.");
        if(n.equals(BigInteger.ZERO))
            return "0";
        String binary = "";
        for(; n.compareTo(BigInteger.ZERO) > 0; n = n.divide(TWO))
            if(n.mod(TWO).equals(BigInteger.ONE))
                binary = '1' + binary;
            else
                binary = '0' + binary;
        return binary;
    }

    public final static BigInteger fastPow(BigInteger coefficient, BigInteger exponent, BigInteger modulus) {
        if(exponent.compareTo(BigInteger.ZERO) < 0)
            exponent = modulus.subtract(exponent.abs().mod(modulus).add(BigInteger.ONE));
        BigInteger result = BigInteger.ONE;
        for(; exponent.compareTo(BigInteger.ZERO) > 0; coefficient = coefficient.pow(2).mod(modulus), exponent = exponent.divide(TWO))
            if(exponent.mod(TWO).equals(BigInteger.ONE))
                result = result.multiply(coefficient).mod(modulus);
        return result;
    }

    public final static Legendre squareModulo(Legendre legendre) {
        BigInteger a = legendre.getValue().abs();
        int n = 0, i = legendre.getValue().compareTo(BigInteger.ZERO) < 0? -1 : 1;
        if(a.compareTo(legendre.getModulus()) > 0)
            a = a.mod(legendre.getModulus());
        for(; a.mod(TWO).equals(BigInteger.ZERO) && a.compareTo(TWO) > 0; a = a.divide(TWO), n++);
        if(n > 0)
            if(quadraticReciprocity(new Legendre(TWO, legendre.getModulus())).equals(Legendre.MIN_ONE))
                if(n % 2 == 1)
                    i *= -1;
        if(a.equals(BigInteger.ONE)) {
            if(BigInteger.valueOf(i).multiply(a).equals(BigInteger.ONE))
                return Legendre.ONE;
            return Legendre.MIN_ONE;
        }
        Legendre R = quadraticReciprocity(new Legendre(a, legendre.getModulus()));
        a = R.getValue().multiply(BigInteger.valueOf(i));
        if(a.equals(BigInteger.ONE))
            return Legendre.ONE;
        else if(a.equals(BigInteger.valueOf(-1)))
            return Legendre.MIN_ONE;
        return squareModulo(new Legendre(a, R.getModulus()));
    }

    private final static Legendre quadraticReciprocity(Legendre legendre) {
        BigInteger a = legendre.getValue().abs(), tmp = BigInteger.valueOf(4);
        if(!a.equals(TWO) && !legendre.getValue().equals(BigInteger.valueOf(-1)))
            if(a.mod(TWO).equals(BigInteger.ZERO) || legendre.getModulus().mod(TWO).equals(BigInteger.ZERO))
                throw new ArithmeticException("Let two integers that are odd.");
        if(legendre.getValue().equals(BigInteger.valueOf(-1)))
            if((tmp = legendre.getModulus().mod(tmp)).equals(BigInteger.ONE))
                return Legendre.ONE;
            else if(tmp.equals(BigInteger.valueOf(3)))
                return Legendre.MIN_ONE;
        if(a.equals(TWO)) {
            if((tmp = legendre.getModulus().mod(BigInteger.valueOf(8))).equals(BigInteger.ONE) || tmp.equals(BigInteger.valueOf(7)))
                return Legendre.ONE;
            else if(tmp.equals(BigInteger.valueOf(3)) || tmp.equals(BigInteger.valueOf(5)))
                return Legendre.MIN_ONE;
        }
        if(a.mod(tmp = BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)) && legendre.getModulus().mod(tmp).equals(BigInteger.valueOf(3)))
            return new Legendre(legendre.getModulus().negate(), a);
        if(a.mod(tmp).equals(BigInteger.ONE) || legendre.getModulus().mod(tmp).equals(BigInteger.ONE))
            return new Legendre(legendre.getModulus(), a);
        return null;
    }

    public final static int galoisFieldsMultiply(int x, int y) {
        int result = 0;
        boolean b;
        for(byte i = 0; i < 8; i++) {
            result = ((y & 0x1) > 0)? result ^ x : result;
            b = ((x & 0x80) > 0);
            x = ((x << 1) & 0xFE);
            if(b)
                x = x ^ 0x1b;
            y = ((y >> 1) & 0x7F);
        }
        return result;
    }
}