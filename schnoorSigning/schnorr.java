package schnoorSigning;

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

public class schnorr {
    private BigInteger p, q, g; // Public parameters
    private BigInteger x, y;    // Private key x, Public key y
    private SecureRandom random = new SecureRandom();

    public void generateKeys() {
        // Generate q and p such that p = qr + 1 and both are prime
        q = BigInteger.probablePrime(64, random); // 64-bit
        BigInteger r;
        do {
            r = new BigInteger(64, random);
            p = q.multiply(r).add(BigInteger.ONE); // Between 64-bit to 128-bit
        } while (!p.isProbablePrime(10));

        // Find a generator g
        BigInteger h, gCandidate;
        do {
            h = new BigInteger(p.bitLength()-1, random); // h < 2^(L) =< p
            gCandidate = h.modPow((p.subtract(BigInteger.ONE)).divide(q), p); // g = h^r mod p
        } while (
            gCandidate.equals(BigInteger.ONE) || 
            h.compareTo(BigInteger.TWO) < 0 || // Ensure 1 < h 
            h.compareTo(p.subtract(BigInteger.ONE)) > 0 // h < p - 1
        ); 
        g = gCandidate;

        // Generate private key x and public key y = g^x mod p
        do {
            x = new BigInteger(q.bitLength(), random);
        } while (x.compareTo(BigInteger.ZERO) <= 0 || x.compareTo(q) >= 0); // reject 0 and q or above
        y = g.modPow(x, p);
    }

    public Signature sign(String message) {
        BigInteger k = new BigInteger(q.bitLength() - 1, random); // h < 2^(N) =< q
        BigInteger r = g.modPow(k, p);
        BigInteger e = hashToBigInt(message + r.toString(), q.bitLength());
        BigInteger s = k.add(x.multiply(e)).mod(q);
        return new Signature(s, e);
    }

    public boolean verify(String message, Signature sig) {
        BigInteger s = sig.s;
        BigInteger e = sig.e;
        BigInteger yPowE = y.modPow(e, p).modInverse(p);
        BigInteger v = g.modPow(s, p).multiply(yPowE).mod(p);
        BigInteger ePrime = hashToBigInt(message + v.toString(), q.bitLength());
        return e.equals(ePrime);
    }

    private BigInteger hashToBigInt(String input, int bits) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            int byteLen = (bits + 7) / 8; // Round up to closest byte to store all bits
            byte[] truncated = Arrays.copyOfRange(hash, 0, byteLen);
            return new BigInteger(1, truncated).mod(BigInteger.ONE.shiftLeft(bits)); // Get N MSB of the digest
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {

        schnorr schnorr = new schnorr();
        schnorr.generateKeys();

        String message = "hello world";
        long startTime = System.nanoTime();
        Signature sig = schnorr.sign(message);
        double runtime = (System.nanoTime() - startTime)/1_000_000_000.0;
        System.out.println("Message: " + message);
        System.out.println("Signature s: " + sig.s);
        System.out.println("Signature e: " + sig.e);
        System.out.println("Verification: " + schnorr.verify(message, sig));
        System.out.println("Runtime for signing: " + runtime + "s");
    }
}
