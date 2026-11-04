package de.g10f.keycloak.credential.hash;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * SSHA Password Hash provider
 *
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 */
public class SSHAPasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String ID = "ssha";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new SSHAPasswordHashProvider(ID);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public void close() {
    }
}
