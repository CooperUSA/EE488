import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class HashGraphAnalyzer {
    static int componentCounter = 0;

    static class NodeInfo {
        int tailLength;
        int cycleLength;
        int componentId;

        NodeInfo(int tail, int cycle, int compId) {
            this.tailLength = tail;
            this.cycleLength = cycle;
            this.componentId = compId;
        }
    }

    static class cHash {
        private MessageDigest md;
        private int k;
        private int numBytes;
        
        public cHash(int k){
            if (k % 8 != 0 || k <= 0 || k > 88) {
                throw new IllegalArgumentException("k must be between 8 and 88 and a multiple of 8");
            }
            this.k = k;
            this.numBytes = k/8;

            try {
                this.md = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("MD5 is not available", e);
            }
        }  

        // Takes a numberical value and hashes it, then gives back the a numerical value of the k LSB
        private long getDigest(long num){
            byte[] digest = null;

            try{
                byte[] inputBytes = ByteBuffer.allocate(Long.BYTES).putLong(num).array();
                digest = this.md.digest(inputBytes);
            } catch (Exception e) {
                System.out.println("Exception " + e);
                System.exit(2);
            }

            long result = 0;
            for (int i = digest.length - numBytes; i < digest.length; i++) {
                result = (result << 8) | (digest[i] & 0xFF);
            }

        return result;
        }
    }


    static Map<Long, NodeInfo> visited = new HashMap<>();
    static List<Integer> tailLengths = new ArrayList<>();
    static List<Integer> cycleLengths = new ArrayList<>();
    static cHash md5;

    public static void main(String[] args) {
        int k = 0;
        try {
            k = Integer.valueOf(args[0]);
            if (k % 8 != 0 || k <= 0 || k > 88) {
                System.out.println("Value must be between 8 and 64 and it has to be a multiple of 8");
                System.exit(1);
            }
        } catch (Exception e) {
            System.out.println("Add int value. Usage: java HashGraphAnalyzer <k>");
            System.exit(1);
        }

        md5 = new cHash(k);

        for (long x = 1; x < (1 << k); x++) {
            if (!visited.containsKey(x)) {
                analyzeComponent(x);
            }
        }

        printStats();
        

        System.out.println("--- full hash mapping ---");
        printHashMapping(k);
    }

    static void printHashMapping(int k) {
        cHash hasher = new cHash(k);
        long limit = (1L << k);
        for (long x = 0; x < limit; x++) {
            long y = hasher.getDigest(x);
            System.out.printf("  %d → %d%n", x, y);
        }
    }

    static void analyzeComponent(long start) {
        long tortoise = md5.getDigest(start);
        long hare = md5.getDigest(md5.getDigest(start));

        // Floyd's Cycle Detection
        while (tortoise != hare) {
            tortoise = md5.getDigest(tortoise);
            hare = md5.getDigest(md5.getDigest(hare));
        }

        // Find tail length (mu)
        int mu = 0;
        tortoise = start;
        while (tortoise != hare) {
            tortoise = md5.getDigest(tortoise);
            hare = md5.getDigest(hare);
            mu++;
        }

        // Find cycle length (lambda)
        int lambda = 1;
        hare = md5.getDigest(tortoise);
        while (tortoise != hare) {
            hare = md5.getDigest(hare);
            lambda++;
        }

        // Store the whole path in visited
        int componentId = componentCounter++;
        long current = start;
        for (int i = 0; i < mu + lambda; i++) {
            visited.put(current, new NodeInfo(mu, lambda, componentId));
            current = md5.getDigest(current);
        }

        tailLengths.add(mu);
        cycleLengths.add(lambda);
    }

    static void printStats() {
        System.out.println("Total Components: " + componentCounter);
        System.out.printf("Tail Lengths: Avg=%.2f" + 
                            " Max=" + max(tailLengths) + "\n", 
                            avg(tailLengths));
        System.out.printf("Cycle Lengths: Min=" + min(cycleLengths) +
                           " Avg=%.2f" +
                           " Max=" + max(cycleLengths) + "\n",
                           avg(cycleLengths));
    }

    static double avg(List<Integer> list) {
        return list.stream().mapToInt(Integer::intValue).average().orElse(0);
    }

    static int min(List<Integer> list) {
        return list.stream().mapToInt(Integer::intValue).min().orElse(0);
    }

    static int max(List<Integer> list) {
        return list.stream().mapToInt(Integer::intValue).max().orElse(0);
    }
}