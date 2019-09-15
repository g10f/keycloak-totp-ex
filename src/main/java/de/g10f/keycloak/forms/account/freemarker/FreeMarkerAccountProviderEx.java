package de.g10f.keycloak.forms.account.freemarker;

import de.g10f.keycloak.forms.account.freemarker.model.TotpBeanEx;
import org.jboss.logging.Logger;
import org.keycloak.forms.account.AccountPages;
import org.keycloak.forms.account.AccountProvider;
import org.keycloak.forms.account.freemarker.FreeMarkerAccountProvider;
import org.keycloak.forms.account.freemarker.model.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.FreeMarkerUtil;
import org.keycloak.theme.Theme;
import org.keycloak.theme.beans.AdvancedMessageFormatterMethod;
import org.keycloak.theme.beans.LocaleBean;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.util.*;

public class FreeMarkerAccountProviderEx extends FreeMarkerAccountProvider {
    // Use TotpBeanEx instead of TotpBean Bean for totp page
    private static final Logger logger = Logger.getLogger(FreeMarkerAccountProviderEx.class);
    private boolean authorizationSupported;

    public FreeMarkerAccountProviderEx(KeycloakSession session, FreeMarkerUtil freeMarker) {
        super(session, freeMarker);
    }

    @Override
    public AccountProvider setFeatures(boolean identityProviderEnabled, boolean eventsEnabled, boolean passwordUpdateSupported, boolean authorizationSupported) {
        this.identityProviderEnabled = identityProviderEnabled;
        this.eventsEnabled = eventsEnabled;
        this.passwordUpdateSupported = passwordUpdateSupported;
        this.authorizationSupported = authorizationSupported;
        return this;
    }

    @Override
    public Response createResponse(AccountPages page) {
        // Use TotpBeanEx instead of TotpBean Bean for totp page
        Map<String, Object> attributes = new HashMap<>();

        if (this.attributes != null) {
            attributes.putAll(this.attributes);
        }

        Theme theme;
        try {
            theme = getTheme();
        } catch (IOException e) {
            logger.error("Failed to create theme", e);
            return Response.serverError().build();
        }

        Locale locale = session.getContext().resolveLocale(user);
        Properties messagesBundle = handleThemeResources(theme, locale, attributes);

        URI baseUri = uriInfo.getBaseUri();
        UriBuilder baseUriBuilder = uriInfo.getBaseUriBuilder();
        for (Map.Entry<String, List<String>> e : uriInfo.getQueryParameters().entrySet()) {
            baseUriBuilder.queryParam(e.getKey(), e.getValue().toArray());
        }
        URI baseQueryUri = baseUriBuilder.build();

        if (stateChecker != null) {
            attributes.put("stateChecker", stateChecker);
        }

        handleMessages(locale, messagesBundle, attributes);

        if (referrer != null) {
            attributes.put("referrer", new ReferrerBean(referrer));
        }

        if (realm != null) {
            attributes.put("realm", new RealmBean(realm));
        }

        attributes.put("url", new UrlBean(realm, theme, baseUri, baseQueryUri, uriInfo.getRequestUri(), stateChecker));

        if (realm.isInternationalizationEnabled()) {
            UriBuilder b = UriBuilder.fromUri(baseQueryUri).path(uriInfo.getPath());
            attributes.put("locale", new LocaleBean(realm, locale, b, messagesBundle));
        }

        attributes.put("features", new FeaturesBean(identityProviderEnabled, eventsEnabled, passwordUpdateSupported, authorizationSupported));
        attributes.put("account", new AccountBean(user, profileFormData));

        switch (page) {
            case TOTP:
                attributes.put("totp", new TotpBeanEx(session, realm, user, uriInfo.getRequestUriBuilder()));
                break;
            case FEDERATED_IDENTITY:
                attributes.put("federatedIdentity", new AccountFederatedIdentityBean(session, realm, user, uriInfo.getBaseUri(), stateChecker));
                break;
            case LOG:
                attributes.put("log", new LogBean(events));
                break;
            case SESSIONS:
                attributes.put("sessions", new SessionsBean(realm, sessions));
                break;
            case APPLICATIONS:
                attributes.put("applications", new ApplicationsBean(session, realm, user));
                attributes.put("advancedMsg", new AdvancedMessageFormatterMethod(locale, messagesBundle));
                break;
            case PASSWORD:
                attributes.put("password", new PasswordBean(passwordSet));
                break;
            case RESOURCES:
                if (!realm.isUserManagedAccessAllowed()) {
                    return Response.status(Response.Status.FORBIDDEN).build();
                }
                attributes.put("authorization", new AuthorizationBean(session, user, uriInfo));
            case RESOURCE_DETAIL:
                if (!realm.isUserManagedAccessAllowed()) {
                    return Response.status(Response.Status.FORBIDDEN).build();
                }
                attributes.put("authorization", new AuthorizationBean(session, user, uriInfo));
        }

        return processTemplate(theme, page, attributes, locale);
    }
}
