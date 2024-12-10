import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashUtility {

    // Enum for supported hash algorithms
    public enum HashAlgorithm {
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA256("SHA-256");

        private final String algorithm;

        HashAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }

    // Function to hash a string using a specified algorithm
    public static String hashString(String input, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm.getAlgorithm());
        byte[] hashBytes = digest.digest(input.getBytes());
        return bytesToHex(hashBytes);
    }

    // Function to check if a string matches a given hash with the specified algorithm
    public static boolean verifyHash(String input, String hash, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        String computedHash = hashString(input, algorithm);
        return computedHash.equals(hash);
    }

    // Function to generate a salted hash
    public static String generateSaltedHash(String input, String salt, HashAlgorithm algorithm) throws NoSuchAlgorithmException {
        String saltedInput = input + salt;
        return hashString(saltedInput, algorithm);
    }

    // Helper function to convert byte array to hexadecimal string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static void main(String[] args) {
        try {
            // Example usage
            String input = "password123";
            String salt = "randomSalt";

            // Hash a string
            String hash = hashString(input, HashAlgorithm.SHA256);
            System.out.println("Hashed string: " + hash);

            // Verify hash
            boolean isMatch = verifyHash(input, hash, HashAlgorithm.SHA256);
            System.out.println("Hash matches: " + isMatch);
            
            // Generate salted hash
            String saltedHash = generateSaltedHash(input, salt, HashAlgorithm.SHA256);
            System.out.println("Salted hash: " + saltedHash);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }
}
