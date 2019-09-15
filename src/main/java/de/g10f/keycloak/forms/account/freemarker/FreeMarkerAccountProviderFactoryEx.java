package de.g10f.keycloak.forms.account.freemarker;

import org.keycloak.Config;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.account.AccountProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.theme.FreeMarkerUtil;

public class FreeMarkerAccountProviderFactoryEx implements AccountProviderFactory {

    private FreeMarkerUtil freeMarker;

    @Override
    public AccountProvider create(KeycloakSession session) {
        return new FreeMarkerAccountProviderEx(session, freeMarker);
    }

    @Override
    public void init(Config.Scope config) {
        freeMarker = new FreeMarkerUtil();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {
        freeMarker = null;
    }

    @Override
    public String getId() {
        return "g10f-freemarker";
    }
}
