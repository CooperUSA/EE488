import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class HashGraphAnalyzer {
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
        private int numBytes;
        
        public cHash(int k){
            this.numBytes = k/8;

            try {
                this.md = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("MD5 is not available", e);
            }
        }  

        // Takes a numberical value and hashes it, then gives back the a numerical value of the k LSB
        public long getDigest(long num){
            byte[] inputBytes = ByteBuffer.allocate(Long.BYTES).putLong(num).array();
            byte[] digest = this.md.digest(inputBytes);

            long result = 0;
            for (int i = digest.length - numBytes; i < digest.length; i++) {
                result = (result << 8) | (digest[i] & 0xFF);
            }
            return result;
        }
    }

    static List<Integer> tailLengths = new ArrayList<>();
    static List<Integer> cycleLengths = new ArrayList<>();
    static cHash md5;

    static class UnionFind {
        private final int[] parent;
        private final int[] rank;
        private int count;

        public UnionFind(int size) {
            parent = new int[size];
            rank = new int[size];
            count = size;
            for (int i = 0; i < size; i++) parent[i] = i;
        }

        public int find(int x) {
            if (parent[x] != x) parent[x] = find(parent[x]);
            return parent[x];
        }

        public void union(int x, int y) {
            int rootX = find(x);
            int rootY = find(y);
            if (rootX == rootY) return;

            if (rank[rootX] < rank[rootY]) {
                parent[rootX] = rootY;
            } else if (rank[rootX] > rank[rootY]) {
                parent[rootY] = rootX;
            } else {
                parent[rootY] = rootX;
                rank[rootX]++;
            }
            count--;
        }

        public int count() {
            return count;
        }
    }

    public static void main(String[] args) {
        int k = 16;
        int N = 1 << k;
        UnionFind uf = new UnionFind(N);
        int[] inDeg = new int[N];
        md5 = new cHash(k);

        for (int x = 0; x < N; x++) {
            int y = (int) md5.getDigest(x);
            uf.union(x, y);
            inDeg[y]++;
        }

        // Tail lengths from terminal nodes only
        for (int x = 0; x < N; x++) {
            if (inDeg[x] == 0) {
                tailLengths.add(findTailLength(md5, x));
            }
        }

        // Cycle lengths: one per component root
        Set<Integer> seen = new HashSet<>();
        for (int x = 0; x < N; x++) {
            int root = uf.find(x);
            if (seen.add(root)) {
                cycleLengths.add(findCycleLength(md5, x));
            }
        }

        printStats(uf.count());
    }

    static int findTailLength(cHash h, long start) {
        long tortoise = h.getDigest(start);
        long hare = h.getDigest(h.getDigest(start));

        // Floyd's Cycle Detection
        while (tortoise != hare) {
            tortoise = h.getDigest(tortoise);
            hare = h.getDigest(h.getDigest(hare));
        }

        // Find tail length (mu)
        int mu = 0;
        tortoise = start;
        while (tortoise != hare) {
            tortoise = h.getDigest(tortoise);
            hare = h.getDigest(hare);
            mu++;
        }
        return mu;
    }

    static int findCycleLength(cHash h, long start) {
        long tortoise = h.getDigest(start);
        long hare = h.getDigest(h.getDigest(start));

        while (tortoise != hare) {
            tortoise = h.getDigest(tortoise);
            hare = h.getDigest(h.getDigest(hare));
        }

        // Find cycle length (lambda)
        int lambda = 1;
        hare = h.getDigest(tortoise);
        while (tortoise != hare) {
            hare = h.getDigest(hare);
            lambda++;
        }
        return lambda;
    }

    static void printStats(int componentCount) {
        System.out.println("Total Components: " + componentCount);
        System.out.printf("Tail Lengths: Avg=%.2f Max=%d\n", avg(tailLengths), max(tailLengths));
        System.out.printf("Cycle Lengths: Min=%d Avg=%.2f Max=%d\n", 
                          min(cycleLengths), avg(cycleLengths), max(cycleLengths));
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
