package de.g10f.keycloak.credential.hash;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordCredentialData;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.remote.providers.runonserver.FetchOnServer;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;
import org.keycloak.testsuite.util.oauth.AccessTokenResponse;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Runs {@link SSHAPasswordHashProvider} inside a real Keycloak server, the way it is used in production:
 * users are imported through the admin API with the password hash taken over from LDAP and the algorithm
 * {@code ssha}, then log in with their password.
 *
 * Covers what {@link SSHAPasswordHashProviderTest} can't: that Keycloak finds and loads the provider
 * (service file), accepts the imported hash and re-hashes it on login.
 */
@KeycloakIntegrationTest(config = SSHAPasswordHashProviderIT.ServerConfig.class)
class SSHAPasswordHashProviderIT {

    private static final String PASSWORD = "Ich esse gerne Bratwurst";

    // Same reference hashes as in SSHAPasswordHashProviderTest (generated independently with Python).
    private static final String SHA = "{SHA}yGs+fWum1ZPZlJUYLMQKZI+UDLs=";
    private static final String SSHA = "{SSHA}iD7wgxYkDKOM0/JzXxSDpl7VOpcBAgMEBQYHCA==";
    private static final String SSHA512 = "{SSHA512}0BUE16yD4/wzbY+yHR/x3gWFp99xfY+dwVuAmsmrU2hGs1A/xarhzIgNlI0gV4gIJoDdmFqaKfnMl3reuEhbBAECAwQFBgcI";

    @InjectRealm
    ManagedRealm realm;

    @InjectOAuthClient
    OAuthClient oauth;

    @InjectRunOnServer(permittedPackages = "de.g10f")
    RunOnServerClient runOnServer;

    @Test
    void userWithSshaHashCanLogIn() {
        createUserWithLdapHash("ssha-user", SSHA);

        AccessTokenResponse response = oauth.doPasswordGrantRequest("ssha-user", PASSWORD);
        assertTrue(response.isSuccess(), () -> "login failed: " + response.getError() + " / " + response.getErrorDescription());
    }

    @Test
    void userWithUnsaltedShaHashCanLogIn() {
        createUserWithLdapHash("sha-user", SHA);

        AccessTokenResponse response = oauth.doPasswordGrantRequest("sha-user", PASSWORD);
        assertTrue(response.isSuccess(), () -> "login failed: " + response.getError() + " / " + response.getErrorDescription());
    }

    @Test
    void wrongPasswordIsRejected() {
        createUserWithLdapHash("wrong-password-user", SSHA);

        assertFalse(oauth.doPasswordGrantRequest("wrong-password-user", "wrong password").isSuccess());
    }

    /**
     * The point of the provider: SSHA hashes are only a bridge. After the first successful login Keycloak
     * stores the password with the realm's own algorithm, and the user can still log in afterwards.
     */
    @Test
    void passwordIsRehashedWithRealmAlgorithmOnLogin() {
        String userId = createUserWithLdapHash("rehash-user", SSHA);
        assertEquals(SSHAPasswordHashProviderFactory.ID, passwordAlgorithm(userId));

        assertTrue(oauth.doPasswordGrantRequest("rehash-user", PASSWORD).isSuccess());

        // argon2 is Keycloak's default hash algorithm; the test realm has no password policy.
        assertEquals("argon2", passwordAlgorithm(userId), "password should have been re-hashed");
        assertTrue(oauth.doPasswordGrantRequest("rehash-user", PASSWORD).isSuccess(), "login after re-hash failed");
    }

    @Test
    void userWithSsha512HashCanLogIn() {
        createUserWithLdapHash("ssha512-user", SSHA512);

        AccessTokenResponse response = oauth.doPasswordGrantRequest("ssha512-user", PASSWORD);
        assertTrue(response.isSuccess(), () -> "login failed: " + response.getError() + " / " + response.getErrorDescription());
    }

    /**
     * While passwords are synced from LDAP, the realm uses hashAlgorithm(ssha): the stored hash must stay
     * exactly as synced, otherwise every user who logs in would look changed to the sync.
     */
    @Test
    void storedHashIsNotChangedOnLoginWhenSshaIsRealmHashAlgorithm() {
        String userId = createUserWithLdapHash("synced-user", SSHA);
        realm.updateWithCleanup(r -> r.passwordPolicy("hashAlgorithm(" + SSHAPasswordHashProviderFactory.ID + ")"));

        assertTrue(oauth.doPasswordGrantRequest("synced-user", PASSWORD).isSuccess());
        assertTrue(oauth.doPasswordGrantRequest("synced-user", PASSWORD).isSuccess());

        assertEquals(SSHA, storedHash(userId));
    }

    /** With hashAlgorithm(ssha), passwords set in Keycloak are stored as {SSHA512} and work for login. */
    @Test
    void passwordSetInKeycloakIsStoredAsSsha512WhenSshaIsRealmHashAlgorithm() {
        String userId = createUserWithLdapHash("password-reset-user", SSHA);
        realm.updateWithCleanup(r -> r.passwordPolicy("hashAlgorithm(" + SSHAPasswordHashProviderFactory.ID + ")"));

        CredentialRepresentation newPassword = new CredentialRepresentation();
        newPassword.setType(CredentialRepresentation.PASSWORD);
        newPassword.setValue("new password");
        newPassword.setTemporary(false);
        realm.admin().users().get(userId).resetPassword(newPassword);

        assertTrue(storedHash(userId).startsWith("{SSHA512}"), storedHash(userId));
        assertTrue(oauth.doPasswordGrantRequest("password-reset-user", "new password").isSuccess());
    }

    /** Logins with an unknown username make Keycloak hash a dummy password with the realm's algorithm. */
    @Test
    void unknownUserIsRejectedNormallyWhenSshaIsRealmHashAlgorithm() {
        realm.updateWithCleanup(r -> r.passwordPolicy("hashAlgorithm(" + SSHAPasswordHashProviderFactory.ID + ")"));

        AccessTokenResponse response = oauth.doPasswordGrantRequest("no-such-user", PASSWORD);
        assertEquals("invalid_grant", response.getError(), response.getErrorDescription());
    }

    /**
     * Creates a user whose password is the given LDAP hash, as an import from LDAP would do it.
     * The user gets a complete profile so that no required action blocks the password grant.
     * Returns the user id; the user is removed again after the test.
     */
    private String createUserWithLdapHash(String username, String ldapHash) {
        PasswordCredentialModel imported = PasswordCredentialModel.createFromValues(
                SSHAPasswordHashProviderFactory.ID, null, -1, ldapHash);

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setSecretData(imported.getSecretData());
        credential.setCredentialData(imported.getCredentialData());

        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setFirstName(username);
        user.setLastName(username);
        user.setEmail(username + "@example.org");
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setCredentials(List.of(credential));

        try (Response response = realm.admin().users().create(user)) {
            assertEquals(201, response.getStatus(), () -> response.readEntity(String.class));
            String userId = CreatedResponseUtil.getCreatedId(response);
            realm.cleanup().add(r -> r.users().delete(userId).close());
            return userId;
        }
    }

    /** The stored password hash as Keycloak keeps it; read on the server, the admin API never returns it. */
    private String storedHash(String userId) {
        return runOnServer.fetchString(OnServer.storedHash(userId));
    }

    /**
     * Code that runs inside the Keycloak server. It lives in its own class because the server loads the
     * class that defines the lambda, and this test class references the admin client, which the server lacks.
     */
    static class OnServer {
        static FetchOnServer storedHash(String userId) {
            return session -> {
                RealmModel realmModel = session.getContext().getRealm();
                UserModel user = session.users().getUserById(realmModel, userId);
                return user.credentialManager().getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                        .map(PasswordCredentialModel::createFromCredentialModel)
                        .map(password -> password.getPasswordSecretData().getValue())
                        .findFirst()
                        .orElse(null);
            };
        }
    }

    /** Hash algorithm of the user's stored password, as Keycloak reports it through the admin API. */
    private String passwordAlgorithm(String userId) {
        CredentialRepresentation password = realm.admin().users().get(userId).credentials().stream()
                .filter(c -> CredentialRepresentation.PASSWORD.equals(c.getType()))
                .findFirst()
                .orElseThrow(() -> new AssertionError("user " + userId + " has no password"));
        try {
            return JsonSerialization.readValue(password.getCredentialData(), PasswordCredentialData.class).getAlgorithm();
        } catch (IOException e) {
            throw new AssertionError("credential data could not be read: " + password.getCredentialData(), e);
        }
    }

    public static class ServerConfig implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder config) {
            // The provider has no dependencies besides Keycloak, so this deploys exactly what ships.
            return config.dependencyCurrentProject();
        }
    }
}
