package de.g10f.keycloak.credential;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.UserCache;

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
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        boolean disableTOTP = false, disableHOTP = false;
        if (CredentialModel.OTP.equals(credentialType)) {
            disableTOTP = true;
            disableHOTP = true;
        } else if (CredentialModel.HOTP.equals(credentialType)) {
            disableHOTP = true;

        } else if (CredentialModel.TOTP.equals(credentialType)) {
            disableTOTP = true;
        }
        if (disableHOTP) {
            List<CredentialModel> hotp = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.HOTP);
            for (CredentialModel cred : hotp) {
                getCredentialStore().removeStoredCredential(realm, user, cred.getId());
            }

        }
        if (disableTOTP) {
            List<CredentialModel> totp = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.TOTP);
            if (!totp.isEmpty()) {
                for (CredentialModel cred : totp) {
                    getCredentialStore().removeStoredCredential(realm, user, cred.getId());
                }
            }

        }
        if (disableTOTP || disableHOTP) {
            UserCache userCache = session.userCache();
            if (userCache != null) {
                userCache.evict(realm, user);
            }
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return CredentialModel.TOTP.equals(credentialType);
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        List<CredentialModel> creds = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.TOTP);
        user.getCachedWith().put(OTPCredentialProvider.class.getName() + "." + CredentialModel.TOTP, creds);
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
