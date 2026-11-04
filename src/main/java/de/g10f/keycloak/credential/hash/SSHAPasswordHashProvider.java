package de.g10f.keycloak.credential.hash;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;

/**
 * Verifies password hashes taken over from an LDAP directory, so that imported users can log in with their
 * existing password.
 *
 * With the realm's default hash algorithm, Keycloak re-hashes the password on the first login. With
 * {@code hashAlgorithm(ssha)} in the realm's password policy, stored hashes are never changed on login,
 * which keeps them identical to the LDAP while passwords are still synced from there.
 *
 * Supported formats (prefix is case-insensitive):
 * <ul>
 *     <li>{@code {SHA}}, {@code {SHA256}}, {@code {SHA384}}, {@code {SHA512}}: base64(digest(password))</li>
 *     <li>{@code {SSHA}}, {@code {SSHA256}}, {@code {SSHA384}}, {@code {SSHA512}}: base64(digest(password + salt) + salt)</li>
 * </ul>
 *
 * New hashes are created as {@code {SSHA512}}.
 */
public class SSHAPasswordHashProvider implements PasswordHashProvider {

    /** LDAP hash prefix (upper case) to JDK digest algorithm. */
    private static final Map<String, String> DIGEST_BY_PREFIX = Map.of(
            "{SHA}", "SHA-1",
            "{SSHA}", "SHA-1",
            "{SHA256}", "SHA-256",
            "{SSHA256}", "SHA-256",
            "{SHA384}", "SHA-384",
            "{SSHA384}", "SHA-384",
            "{SHA512}", "SHA-512",
            "{SSHA512}", "SHA-512");

    private static final int SALT_LENGTH = 8;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String providerId;

    public SSHAPasswordHashProvider(String providerId) {
        this.providerId = providerId;
    }

    /**
     * Keycloak asks the provider of the realm's hash algorithm whether a stored password has to be
     * re-hashed on login. Always {@code true} (no re-hash), so with {@code hashAlgorithm(ssha)} the stored
     * value stays exactly as synced from LDAP.
     */
    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return true;
    }

    /**
     * Only used with {@code hashAlgorithm(ssha)} in the realm: creates {@code {SSHA512}} with a random
     * 8 byte salt. SHA has no iterations, so they are ignored.
     */
    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);

        MessageDigest digest = newDigest("SHA-512");
        digest.update(rawPassword.getBytes(StandardCharsets.UTF_8));
        digest.update(salt);
        byte[] digestAndSalt = Arrays.copyOf(digest.digest(), digest.getDigestLength() + SALT_LENGTH);
        System.arraycopy(salt, 0, digestAndSalt, digest.getDigestLength(), SALT_LENGTH);

        String encoded = "{SSHA512}" + Base64.getEncoder().encodeToString(digestAndSalt);
        return PasswordCredentialModel.createFromValues(providerId, null, -1, encoded);
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        String storedHash = credential.getPasswordSecretData().getValue();
        if (storedHash == null || storedHash.isBlank()) {
            throw new IllegalArgumentException("Stored password has no value.");
        }
        storedHash = storedHash.trim();

        int prefixEnd = storedHash.indexOf('}');
        if (!storedHash.startsWith("{") || prefixEnd < 0) {
            throw new IllegalArgumentException("Stored password has no LDAP hash prefix like {SSHA}.");
        }
        String prefix = storedHash.substring(0, prefixEnd + 1).toUpperCase(Locale.ROOT);
        String digestAlgorithm = DIGEST_BY_PREFIX.get(prefix);
        if (digestAlgorithm == null) {
            throw new IllegalArgumentException("Unsupported LDAP password hash prefix " + shortened(prefix)
                    + ", supported are " + new TreeSet<>(DIGEST_BY_PREFIX.keySet()) + ".");
        }

        MessageDigest digest = newDigest(digestAlgorithm);
        // Values copied from LDIF exports may contain line breaks or spaces inside the base64 part.
        String base64 = storedHash.substring(prefixEnd + 1).replaceAll("\\s", "");
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Stored password hash " + prefix + " is not valid base64.", e);
        }

        // Salted formats append the salt after the digest (an empty salt is valid); unsalted formats are
        // exactly one digest long.
        boolean salted = prefix.startsWith("{SSHA");
        int digestLength = digest.getDigestLength();
        if (salted ? decoded.length < digestLength : decoded.length != digestLength) {
            throw new IllegalArgumentException("Stored password hash " + prefix + " has " + decoded.length
                    + " bytes, which does not fit a " + digestAlgorithm + " digest of " + digestLength + " bytes.");
        }
        byte[] expectedDigest = Arrays.copyOfRange(decoded, 0, digestLength);
        byte[] salt = Arrays.copyOfRange(decoded, digestLength, decoded.length);

        digest.update(rawPassword.getBytes(StandardCharsets.UTF_8));
        digest.update(salt);
        // Constant-time comparison, so the response time does not reveal how much of the hash matched.
        return MessageDigest.isEqual(expectedDigest, digest.digest());
    }

    /** The prefix comes from stored data and may be arbitrarily long; keep log messages short. */
    private static String shortened(String prefix) {
        return prefix.length() <= 20 ? prefix : prefix.substring(0, 20) + "...";
    }

    private static MessageDigest newDigest(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The JVM does not provide the digest " + algorithm + ".", e);
        }
    }

    @Override
    public void close() {
    }
}
