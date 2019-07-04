
package de.g10f.keycloak.credential;

import org.keycloak.Config;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.DisplayTypeAuthenticatorFactory;
import org.keycloak.authentication.authenticators.console.ConsoleOTPFormAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 * @version $Revision: 1 $
 */
public class TOTPFormAuthenticatorFactory implements AuthenticatorFactory, DisplayTypeAuthenticatorFactory {

    public static final String PROVIDER_ID = "auth-g10f-totp-form";
    public static final TOTPFormAuthenticator SINGLETON = new TOTPFormAuthenticator();

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public Authenticator createDisplay(KeycloakSession session, String displayType) {
        if (displayType == null) return SINGLETON;
        if (!OAuth2Constants.DISPLAY_CONSOLE.equalsIgnoreCase(displayType)) return null;
        return ConsoleOTPFormAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.TOTP;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.OPTIONAL,
            AuthenticationExecutionModel.Requirement.DISABLED};

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "TOTP Form (g10f)";
    }

    @Override
    public String getHelpText() {
        return "Validates a TOTP on a separate TOTP form.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }
}
