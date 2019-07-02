
package de.g10f.keycloak.rest;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 */
public class UserResourceProvider implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(UserResourceProvider.class);

    private KeycloakSession session;

    public UserResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new UserResource(session);
    }

    @Override
    public void close() {
    }

}
