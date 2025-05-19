package schnorrSigning;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

class Signature {
    public BigInteger s, e;

    public Signature(BigInteger s, BigInteger e) {
        this.s = s;
        this.e = e;
    }
}

public class Schnorr {
    private BigInteger p, q, g; // Public parameters
    private BigInteger x, y;    // Private key x, Public key y
    private SecureRandom random = new SecureRandom();

    private int L = 2048;   // p ∈ [2^(L-1), 2^(L)-1], p: 2048-bit
    private int N = 256;    // q ∈ [2^(N-1), 2^(N)-1], q: 256-bit

    public void generateKeys() {
        // Generate q and p such that p = qr + 1 and both are prime [Question 7]
        q = BigInteger.probablePrime(N, random); 
        BigInteger r;
        do {
            r = new BigInteger(L-N, random).setBit(L-N-1);      // Ensure r is exactly (L-N)-bit to make p exactly L bits
            p = q.multiply(r).add(BigInteger.ONE);
        } while (!p.isProbablePrime(10) || p.bitLength() != L);

        // Find a generator g
        BigInteger h, gCandidate;
        do {
            h = new BigInteger(L-1, random);                    // h ∈ [2, 2^(L-1)-1] < p
            gCandidate = h.modPow((p.subtract(BigInteger.ONE)).divide(q), p); // g = h^r mod p
        } while (
            gCandidate.equals(BigInteger.ONE) || 
            h.compareTo(BigInteger.TWO) < 0 ||                  // Ensure 1 < h 
            h.compareTo(p.subtract(BigInteger.ONE)) > 0         // h < p - 1
        ); 
        g = gCandidate;

        // Generate private key x and public key y = g^x mod p
        do {
            x = new BigInteger(N-1, random);                    // x ∈ [1, 2^(L-1)-1] < q
        } while (x.compareTo(BigInteger.ONE) < 0 || x.compareTo(q) >= 0); // reject 0 and q or above
        y = g.modPow(x, p);
    }

    public Signature sign(String message) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();// To concatenate m and r
        byte[] mBytes = message.getBytes(StandardCharsets.UTF_8);

        BigInteger k = new BigInteger(N-1, random);             // k ∈ [1, 2^(L-1)-1] < q
        byte[] rBytes = g.modPow(k, p).toByteArray();
        out.write(mBytes);
        out.write(rBytes); 
        BigInteger e = hashToBigInt(out.toByteArray(), N);
        BigInteger s = k.add(x.multiply(e)).mod(q);
        return new Signature(s, e);
    }

    public boolean verify(String message, Signature sig) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();// To concatenate m and v
        byte[] mBytes = message.getBytes(StandardCharsets.UTF_8);

        BigInteger s = sig.s;
        BigInteger e = sig.e;
        BigInteger yPowE = y.modPow(e, p).modInverse(p);
        byte[] vBytes = g.modPow(s, p).multiply(yPowE).mod(p).toByteArray();
        out.write(mBytes);
        out.write(vBytes); 
        BigInteger ePrime = hashToBigInt(out.toByteArray(), q.bitLength());
        return e.equals(ePrime);
    }

    // Miller-Rabin primality test for numbers of bit length 2048, so for "p" [Question 6]
    public boolean millerRabinP(BigInteger n, int t) {
        // Step 1: Write n−1 = 2^s * r, with r odd
        BigInteger r = n.subtract(BigInteger.ONE);
        int s = 0;
    
        while (r.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            r = r.shiftRight(1);
            s++;
        }
    
        // Step 2: For i from 1 to t do the following
        for (int i = 0; i < t; i++) {
            // Step 2.1: Choose random a ∈ [2, n−2]
            BigInteger a;
            do {
                a = new BigInteger(n.bitLength()-1, random);
            } while (a.compareTo(BigInteger.TWO) < 0 || a.compareTo(n.subtract(BigInteger.TWO)) > 0);
            
            // Step 2.2: Compute y = a^r mod n
            BigInteger yMi = a.modPow(r, n);

            // Step 2.3
            if (yMi.equals(BigInteger.ONE) || yMi.equals(n.subtract(BigInteger.ONE))) continue;
    
            boolean found = false;
            for (int j = 1; j < s; j++) {
                yMi = yMi.modPow(BigInteger.TWO, n);
                if (yMi.equals(n.subtract(BigInteger.ONE))) {
                    found = true;
                    break;
                }
                if (yMi.equals(BigInteger.ONE)) return false;
            }
    
            if (!found) return false;
        }
    
        return true;
    } 

    // Validate the parameters [Question 7]
    private boolean validateParameters() {
        
        if (!millerRabinP(p, 20)) return false;                 // Greater than 99.99% certainty that p is prime
        if (!millerRabinP(q, 20)) return false;                 // Greater than 99.99% certainty that q is prime
        if (!p.subtract(BigInteger.ONE).mod(q).equals(BigInteger.ZERO)) return false;   // q | (p-1)
        if (!g.modPow(q, p).equals(BigInteger.ONE)) return false; // g^q (mod p) != 1
        if (g.equals(BigInteger.ONE)) return false;               // g !≡ 1 (mod p)
        return true;
    }

    private BigInteger hashToBigInt(byte[] input, int bits) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input);
            int byteLen = (bits + 7) / 8; // Round up to closest byte to store all bits
            byte[] truncated = Arrays.copyOfRange(hash, 0, byteLen);
            return new BigInteger(1, truncated).mod(BigInteger.ONE.shiftLeft(bits)); // Get N MSB of the digest
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) throws IOException {

        Schnorr schnorr = new Schnorr();
        schnorr.generateKeys();

        String message = "hello world";
        
        long startTime = System.nanoTime();
        Signature sig = schnorr.sign(message);
        boolean valid = schnorr.validateParameters();
        double runtime = (System.nanoTime() - startTime)/1_000_000_000.0;
        
        System.out.println("Message: " + message);
        System.out.println("Signature s: " + sig.s);
        System.out.println("Signature e: " + sig.e);
        System.out.println("Verification: " + schnorr.verify(message, sig));
        System.out.println("Valid parameters: " + valid);
        System.out.println("Runtime for signing and verifying: " + runtime + "s");
    }
}
