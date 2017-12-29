package com.murez.test;

import java.math.BigInteger;
import com.murez.branch.crypto.ECElGamal;
import com.murez.branch.util.ECPoint;
import com.murez.branch.util.EllipticCurve;

public class Main {
    public static void main(String[] args) {

    }

    private static void oldScenario() {
        EllipticCurve E = new EllipticCurve(BigInteger.valueOf(190460112), BigInteger.valueOf(187944061), new BigInteger("682782445026322639"));
        ECPoint P = new ECPoint(new BigInteger("466375425072200120"), new BigInteger("391502737373712908"));
        BigInteger N = new BigInteger("23490183987");
        ECPoint Q = P.sum(N, E);
        int i, j, c, multiply = 100, n = 100;
        try {
            java.io.OutputStreamWriter writer = new java.io.OutputStreamWriter(new java.io.FileOutputStream("q:/test.txt"), java.nio.charset.StandardCharsets.ISO_8859_1);
            for(i = 0; i < 32 * n; i++) {
                do { c = new java.util.Random().nextInt(127); }
                while(c <= 32 || c > 126);
                writer.write((char) c);
            }
            writer.close();
        } catch(java.io.IOException e) { e.printStackTrace(); }
        System.out.println("writing has finished!");

        java.text.DecimalFormat f = new java.text.DecimalFormat("0.0000");
        char[] chars = new char[32];
        ECElGamal ecg = new ECElGamal(E, P);
        long start = 0, end = 0;
        String cipher = "";
        long[] ends = new long[multiply];
        try {
            java.io.InputStreamReader reader = new java.io.InputStreamReader(new java.io.FileInputStream("q:/test.txt"), java.nio.charset.StandardCharsets.ISO_8859_1);
            for(i = 0; i < multiply; i++)
                for(cipher = "", j = 0; j < n; j++) {
                    reader.read(chars);
                    cipher += ecg.encrypt(new String(chars), Q);
                    start = System.nanoTime();
                    ecg.decrypt(cipher, N);
                    ends[i] = System.nanoTime() - start;
                }
            reader.close();
        } catch(java.io.IOException e) { e.printStackTrace(); }
        for(i = 0; i < multiply; i++)
            end += ends[i];
        System.out.print(f.format(end / 1000000000.));
    }
	/*
	private String createPublicKey() {
		int requestId = 4;
		EllipticCurve E = EllipticCurve.generate(ECElGamal.LEVEL_NORMAL);
		ECPoint P = ECPoint.getRandPoint(E);
		long privateKey = 939238209;
		ECPoint Q = P.sum(BigInteger.valueOf(privateKey), E);
		String publicKey = new Convert().toString(new ECPoint[][] {
			new ECPoint[] { new ECPoint(BigInteger.valueOf(requestId), E.getField()), new ECPoint(E.getA(), E.getB()) },
			new ECPoint[] { P, Q }
		});
		return publicKey;
	}

	private String sendCipher(int requestId, EllipticCurve E, ECPoint P, ECPoint publicKey) {
		String key = "hadnI<3azeR", message = "Indah Dwi Yanti Purba loves Muhammad Reza Nasution forever and always";
		String cipher = new Convert().toReadableCipher(new Rijndael(key).encrypt(message));
		String cipherKey = new ECElGamal(E, P).encrypt(key, publicKey);
		return String.valueOf(requestId) + (char) 0 + cipherKey + (char) 0 + cipher;
	}

	private String extractCipher(String cipher) {
		int[] lines = new int[2];
		int i = 0, j = 0;
		for(; i < cipher.length(); i++)
			if(cipher.charAt(i) == 0) {
				lines[j++] = i;
				if(j >= lines.length) break;
			}
		//int requestId = Integer.parseInt(cipher.substring(0, lines[1]));
		String cipherKey = cipher.substring(lines[0] + 1, lines[1]);
		cipher = cipher.substring(lines[1], cipher.length());

		return cipherKey;
	}*/
}