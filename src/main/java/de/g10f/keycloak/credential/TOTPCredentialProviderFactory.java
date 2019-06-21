package de.g10f.keycloak.credential;

import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

/**
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 * @version $Revision: 1 $
 */
public class TOTPCredentialProviderFactory implements CredentialProviderFactory<TOTPCredentialProvider> {
    public static final String PROVIDER_ID = "g10f-totp";

    @Override
    public TOTPCredentialProvider create(KeycloakSession session) {
        return new TOTPCredentialProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

}
