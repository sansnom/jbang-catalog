import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.UUID;

public class Id {

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: jbang id@sansnom <prefix_base62id>");
            System.out.println("Usage: jbang id@sansnom <UUID> [prefix]");
            return;
        }
        String id = args[0];
        if (id.contains("_")) {
            System.out.println(fromString(id));
        } else {
            String prefix = args.length > 1 ? args[1] : "prefix";
            System.out.println(toPrintable(UUID.fromString(id), prefix));
        }
    }

    private static UUID fromString(String id) {
        String substring = id.substring(id.indexOf("_") + 1);
        byte[] decode = Base62.decode(substring);
        return uuidFromBytes(decode);
    }

    private static String toPrintable(UUID uuid, String prefix) {
        byte[] bytes = uuidToBytes(uuid);
        String encoded = Base62.encode(bytes);
        return prefix + "_" + encoded;
    }

    private static UUID uuidFromBytes(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        long mostSigBits = buffer.getLong();
        long leastSigBits = buffer.getLong();
        return new UUID(mostSigBits, leastSigBits);
    }

    private static byte[] uuidToBytes(UUID uuid) {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putLong(uuid.getMostSignificantBits());
        buffer.putLong(uuid.getLeastSignificantBits());
        return buffer.array();
    }

    private static class Base62 {
        private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        private static final int BASE = ALPHABET.length();

        public static String encode(byte[] input) {
            BigInteger bi = new BigInteger(1, input);
            StringBuilder sb = new StringBuilder();
            while (bi.compareTo(BigInteger.ZERO) > 0) {
                int mod = bi.mod(BigInteger.valueOf(BASE)).intValue();
                sb.append(ALPHABET.charAt(mod));
                bi = bi.divide(BigInteger.valueOf(BASE));
            }
            return sb.reverse().toString();
        }

        public static byte[] decode(String input) {
            BigInteger bi = BigInteger.ZERO;
            for (int i = 0; i < input.length(); i++) {
                bi = bi.multiply(BigInteger.valueOf(BASE));
                int index = ALPHABET.indexOf(input.charAt(i));
                if (index == -1) {
                    throw new IllegalArgumentException("Invalid character: " + input.charAt(i));
                }
                bi = bi.add(BigInteger.valueOf(index));
            }
            byte[] bytes = bi.toByteArray();
            if (bytes.length > 1 && bytes[0] == 0) {
                byte[] tmp = new byte[bytes.length - 1];
                System.arraycopy(bytes, 1, tmp, 0, tmp.length);
                return tmp;
            }
            return bytes;
        }
    }
}
