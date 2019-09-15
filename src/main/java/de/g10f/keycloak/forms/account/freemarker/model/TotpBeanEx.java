package de.g10f.keycloak.forms.account.freemarker.model;

import org.keycloak.credential.CredentialModel;
import org.keycloak.forms.account.freemarker.model.TotpBean;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.UriBuilder;
import java.util.List;

import static de.g10f.keycloak.credential.TOTPCredentialProvider.EX_DEVICE;

public class TotpBeanEx extends TotpBean {
    private final long countTOTPCredentials;
    private final long countTOTPExCredentials;

    public TotpBeanEx(KeycloakSession session, RealmModel realm, UserModel user, UriBuilder uriBuilder) {
        super(session, realm, user, uriBuilder);
        List<CredentialModel> otpCredentials = session.userCredentialManager().getStoredCredentialsByType(realm, user, realm.getOTPPolicy().getType());

        countTOTPExCredentials = otpCredentials.stream().filter(c -> EX_DEVICE.equals(c.getDevice())).count();
        countTOTPCredentials = otpCredentials.stream().filter(c -> !EX_DEVICE.equals(c.getDevice())).count();
    }

    public long getCountTOTPCredentials() {
        return countTOTPCredentials;
    }

    public long getcountTOTPExCredentials() {
        return countTOTPExCredentials;
    }
}
