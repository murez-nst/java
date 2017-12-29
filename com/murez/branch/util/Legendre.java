package com.murez.branch.util;

import java.math.BigInteger;

public class Legendre {
    public static final Legendre ONE = new Legendre(1), MIN_ONE = new Legendre(-1);
    private BigInteger value, modulus;
    private boolean single;

    public Legendre(BigInteger oddNumber, BigInteger modulus) {
        if(modulus.compareTo(BigInteger.ZERO) <= 0)
            throw new ArithmeticException("Modulus must be positive.");
        value = oddNumber;
        this.modulus = modulus;
    }

    private Legendre(int value) {
        this.value = BigInteger.valueOf(value);
        single = true;
    }

    public BigInteger getValue() {
        return value;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public String toString() {
        if(single)
            return value.toString();
        boolean b = value.compareTo(BigInteger.ZERO) < 0;
        return (b? "-(" : "") + value.abs() + " / " + modulus + (b? ")" : "");
    }
}