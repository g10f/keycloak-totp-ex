package de.g10f.keycloak.credential;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.*;

import java.util.List;


/**
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 * @version $Revision: 1 $
 */
public class TOTPCredentialProvider extends OTPCredentialProvider {
    private static final Logger logger = Logger.getLogger(OTPCredentialProvider.class);


    public TOTPCredentialProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return "totp".equals(credentialType);
    }


    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;

        }
        String token = ((UserCredentialModel) input).getValue();
        if (token == null) {
            return false;
        }

        OTPPolicy policy = realm.getOTPPolicy();
        if (realm.getOTPPolicy().getType().equals(CredentialModel.TOTP)) {
            TimeBasedOTPEx validator = new TimeBasedOTPEx(policy.getAlgorithm(), policy.getDigits(), policy.getPeriod(), policy.getLookAheadWindow());
            List<CredentialModel> creds = getCachedCredentials(user, CredentialModel.TOTP);
            if (creds == null) {
                creds = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.TOTP);
            } else {
                logger.debugv("Cache hit for TOTP for user {0}", user.getUsername());
            }
            for (CredentialModel cred : creds) {
                if (validator.validateTOTP(token, cred.getValue().getBytes())) {
                    return true;
                }
            }
        }
        return false;
    }
}
