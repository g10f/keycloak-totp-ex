package de.g10f.keycloak.credential;

import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.OTPCredentialProvider;
import org.keycloak.models.*;
import org.keycloak.models.cache.UserCache;
import org.keycloak.models.utils.TimeBasedOTP;

import java.util.List;


/**
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 * @version $Revision: 1 $
 */
public class TOTPCredentialProvider extends OTPCredentialProvider {
    public static final String EX_DEVICE = "ex";
    private static final Logger logger = Logger.getLogger(OTPCredentialProvider.class);

    public TOTPCredentialProvider(KeycloakSession session) {
        super(session);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) return false;

        if (!(input instanceof UserCredentialModel)) {
            logger.debug("Expected instance of UserCredentialModel for CredentialInput");
            return false;
        }
        UserCredentialModel inputModel = (UserCredentialModel) input;
        CredentialModel model = null;
        if (inputModel.getDevice() != null) {
            model = getCredentialStore().getStoredCredentialByNameAndType(realm, user, inputModel.getDevice(), CredentialModel.TOTP);
            if (model == null) {
                model = getCredentialStore().getStoredCredentialByNameAndType(realm, user, inputModel.getDevice(), CredentialModel.HOTP);
            }
        }
        if (model == null) {
            String device = ((UserCredentialModel) input).getDevice();
            if (EX_DEVICE.equals(device)) {
                // if creating a new external Credential, only delete external Credentials
                disableCredentialTypeEx(realm, user, CredentialModel.OTP);
            } else {
                // delete all non ex
                disableCredentialType(realm, user, CredentialModel.OTP);
            }
            model = new CredentialModel();
        }

        OTPPolicy policy = realm.getOTPPolicy();
        model.setDigits(policy.getDigits());
        model.setCounter(policy.getInitialCounter());
        model.setAlgorithm(policy.getAlgorithm());
        model.setType(input.getType());
        model.setValue(inputModel.getValue());
        model.setDevice(inputModel.getDevice());
        model.setPeriod(policy.getPeriod());
        model.setCreatedDate(Time.currentTimeMillis());
        if (model.getId() == null) {
            getCredentialStore().createCredential(realm, user, model);
        } else {
            getCredentialStore().updateCredential(realm, user, model);
        }
        UserCache userCache = session.userCache();
        if (userCache != null) {
            userCache.evict(realm, user);
        }
        return true;

    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // only delete non ex TOTP secrets
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
                // only delete non ex credentials
                if (!EX_DEVICE.equals(cred.getDevice())) {
                    getCredentialStore().removeStoredCredential(realm, user, cred.getId());
                }
            }
        }
        if (disableTOTP) {
            List<CredentialModel> totp = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.TOTP);
            if (!totp.isEmpty()) {
                for (CredentialModel cred : totp) {
                    // only delete non ex credentials
                    if (!EX_DEVICE.equals(cred.getDevice())) {
                        getCredentialStore().removeStoredCredential(realm, user, cred.getId());
                    }
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

    public void disableCredentialTypeEx(RealmModel realm, UserModel user, String credentialType) {
        // only delete ex credentials
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
                // only delete ex credentials
                if (EX_DEVICE.equals(cred.getDevice())) {
                    getCredentialStore().removeStoredCredential(realm, user, cred.getId());
                }
            }
        }
        if (disableTOTP) {
            List<CredentialModel> totp = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.TOTP);
            if (!totp.isEmpty()) {
                for (CredentialModel cred : totp) {
                    // only delete ex credentials
                    if (EX_DEVICE.equals(cred.getDevice())) {
                        getCredentialStore().removeStoredCredential(realm, user, cred.getId());
                    }
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
            TimeBasedOTP validator;
            List<CredentialModel> creds = getCachedCredentials(user, CredentialModel.TOTP);
            if (creds == null) {
                creds = getCredentialStore().getStoredCredentialsByType(realm, user, CredentialModel.TOTP);
            } else {
                logger.debugv("Cache hit for TOTP for user {0}", user.getUsername());
            }
            for (CredentialModel cred : creds) {
                String device = cred.getDevice();
                if (EX_DEVICE.equals(device)) {
                    // use our special validator
                    validator = new TimeBasedOTPEx(policy.getAlgorithm(), policy.getDigits(), policy.getPeriod(), policy.getLookAheadWindow());
                } else {
                    validator = new TimeBasedOTP(policy.getAlgorithm(), policy.getDigits(), policy.getPeriod(), policy.getLookAheadWindow());
                }
                if (validator.validateTOTP(token, cred.getValue().getBytes())) {
                    return true;
                }
            }
        }
        return false;
    }
}
