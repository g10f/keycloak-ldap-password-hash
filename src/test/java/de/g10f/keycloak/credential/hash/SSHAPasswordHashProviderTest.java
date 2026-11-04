package de.g10f.keycloak.credential.hash;

import org.junit.jupiter.api.Test;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.credential.PasswordCredentialModel;

import static org.junit.jupiter.api.Assertions.*;

public class SSHAPasswordHashProviderTest {

    private static final String PASSWORD = "Ich esse gerne Bratwurst";

    // Reference hashes for PASSWORD, generated independently with Python's hashlib
    // (salt 0x0102030405060708 for the salted variants), in the format LDAP servers store them.
    private static final String SHA = "{SHA}yGs+fWum1ZPZlJUYLMQKZI+UDLs=";
    private static final String SSHA = "{SSHA}iD7wgxYkDKOM0/JzXxSDpl7VOpcBAgMEBQYHCA==";
    private static final String SHA256 = "{SHA256}SSDmw/exBt4OoB66vVFmwuweOtOlCuneq/x34njClXU=";
    private static final String SSHA256 = "{SSHA256}dR/aWEmtsUuziePLPKBghFZkavMS+9EzYTpcJcKi70oBAgMEBQYHCA==";
    private static final String SHA384 = "{SHA384}/+jYyPLRTU+Z+CZYe/1c1cURs73WQvS7dtESDtwKxBkX6bqlkLiHa8jWo+3geY4O";
    private static final String SSHA384 = "{SSHA384}eDMEDrz69gvPzqfaGgw17nHMDGFMWeXDqTAHpKc5iC21uLASbj0nWyIN5PeL+lHIAQIDBAUGBwg=";
    private static final String SHA512 = "{SHA512}m5UY1sJnr6BdgFpYiyRit7EBSNbfrOudy2pI2I5U8x4RvxPGzjuLBBU4XPEGZPENWjEppJbov65FXb4Jtu2ujg==";
    private static final String SSHA512 = "{SSHA512}0BUE16yD4/wzbY+yHR/x3gWFp99xfY+dwVuAmsmrU2hGs1A/xarhzIgNlI0gV4gIJoDdmFqaKfnMl3reuEhbBAECAwQFBgcI";

    private final PasswordHashProvider provider = new SSHAPasswordHashProviderFactory().create(null);

    private boolean verify(String rawPassword, String storedHash) {
        PasswordCredentialModel credential = PasswordCredentialModel.createFromValues(
                SSHAPasswordHashProviderFactory.ID, null, -1, storedHash);
        return provider.verify(rawPassword, credential);
    }

    @Test
    public void verifiesSha1Hashes() {
        assertTrue(verify(PASSWORD, SHA));
        assertTrue(verify(PASSWORD, SSHA));
        // Hash created by Spring's LdapShaPasswordEncoder, which earlier versions of this provider used.
        assertTrue(verify(PASSWORD, "{SSHA}A95jbMDX8Mi3YC2MpZ8IlTIVu6QOka/mM7/XiQ=="));
    }

    @Test
    public void verifiesSha2Hashes() {
        assertTrue(verify(PASSWORD, SHA256));
        assertTrue(verify(PASSWORD, SSHA256));
        assertTrue(verify(PASSWORD, SHA384));
        assertTrue(verify(PASSWORD, SSHA384));
        assertTrue(verify(PASSWORD, SHA512));
        assertTrue(verify(PASSWORD, SSHA512));
    }

    @Test
    public void prefixIsCaseInsensitive() {
        assertTrue(verify(PASSWORD, SSHA512.replace("{SSHA512}", "{ssha512}")));
    }

    @Test
    public void passwordIsHashedAsUtf8() {
        // Reference generated with Python from "Grüße aus Köln ß €".encode("utf-8").
        String hash = "{SSHA512}H/bD5TmA2Q3iQ5ugyZ6lagwSiXmAE24NM+NxD01DRfig4cqZy8BZIim/DzjAzJ7q5nvCuI3hpaGlBccfHxbBwgECAwQFBgcI";
        assertTrue(verify("Grüße aus Köln ß €", hash));
    }

    @Test
    public void saltedFormatWithEmptySaltIsAccepted() {
        // digest(password + "") without salt bytes is a valid, if pointless, salted hash.
        assertTrue(verify(PASSWORD, SHA.replace("{SHA}", "{SSHA}")));
    }

    @Test
    public void whitespaceAndLineBreaksInStoredValueAreIgnored() {
        String withLineBreak = "{SSHA512}0BUE16yD4/wzbY+yHR/x3gWFp99xfY+dwVuAmsmr\n U2hGs1A/xarhzIgNlI0gV4gIJoDdmFqaKfnMl3reuEhbBAECAwQFBgcI";
        assertTrue(verify(PASSWORD, withLineBreak));
        assertTrue(verify(PASSWORD, " " + SSHA512 + "\n"));
    }

    @Test
    public void rejectsWrongPassword() {
        assertFalse(verify("wrong password", SHA));
        assertFalse(verify("wrong password", SSHA));
        assertFalse(verify("wrong password", SSHA512));
        assertFalse(verify("", SSHA512));
    }

    @Test
    public void missingOrEmptyValueFails() {
        assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, null));
        assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, ""));
    }

    @Test
    public void invalidBase64Fails() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, "{SSHA512}not*base64"));
        assertTrue(e.getMessage().contains("base64"), e.getMessage());
    }

    @Test
    public void longUnknownPrefixIsShortenedInMessage() {
        String longPrefix = "{" + "X".repeat(200) + "}";
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, longPrefix + "abc"));
        assertFalse(e.getMessage().contains(longPrefix), e.getMessage());
    }

    @Test
    public void unsupportedPrefixFailsWithClearMessage() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> verify(PASSWORD, "{MD5}X03MO1qnZdYdgyfeuILPmQ=="));
        assertTrue(e.getMessage().contains("{MD5}"), e.getMessage());
    }

    @Test
    public void missingPrefixFails() {
        assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, "plaintext"));
        assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, "{SSHA512"));
    }

    @Test
    public void hashWithWrongLengthFails() {
        // A SHA-1 digest stored under the SHA-512 prefix must not be accepted as "digest + salt".
        assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, SHA.replace("{SHA}", "{SSHA512}")));
        // An unsalted hash must be exactly one digest long.
        assertThrows(IllegalArgumentException.class, () -> verify(PASSWORD, SSHA.replace("{SSHA}", "{SHA}")));
    }

    @Test
    public void createsSsha512WithRandomSalt() {
        PasswordCredentialModel first = provider.encodedCredential(PASSWORD, -1);
        PasswordCredentialModel second = provider.encodedCredential(PASSWORD, -1);
        String firstHash = first.getPasswordSecretData().getValue();

        assertTrue(firstHash.startsWith("{SSHA512}"), firstHash);
        // 64 byte digest + 8 byte salt
        assertEquals(72, java.util.Base64.getDecoder().decode(firstHash.substring("{SSHA512}".length())).length);
        assertNotEquals(firstHash, second.getPasswordSecretData().getValue(), "salt must be random");
        assertTrue(provider.verify(PASSWORD, first));
        assertFalse(provider.verify("wrong password", first));
    }
}
