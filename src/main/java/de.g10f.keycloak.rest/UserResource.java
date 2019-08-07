package de.g10f.keycloak.rest;

import de.g10f.keycloak.credential.TOTPCredentialProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;

/**
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 */
public class UserResource {

    private final KeycloakSession session;
    private final AuthenticationManager.AuthResult auth;

    public UserResource(KeycloakSession session) {
        this.session = session;
        this.auth = new AppAuthManager().authenticateBearerToken(session, session.getContext().getRealm());
    }

    @Path("{username}/totp-ex")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void resetTOTPEx(final @PathParam("username") String username, CredentialRepresentation totp) {
        checkRealmAdmin();
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(username, realm);
        if (totp == null || totp.getValue() == null || !CredentialRepresentation.TOTP.equals(totp.getType())) {
            throw new org.jboss.resteasy.spi.BadRequestException("No TOTP provided");
        }
        if (Validation.isBlank(totp.getValue())) {
            throw new org.jboss.resteasy.spi.BadRequestException("Empty TOTP secret not allowed");
        }
        UserCredentialModel cred = UserCredentialModel.totp(totp.getValue());
        cred.setDevice(totp.getDevice());
        session.userCredentialManager().updateCredential(realm, user, cred);
        //adminEvent.operation(OperationType.ACTION).resourcePath(session.getContext().getUri()).success();
    }

    private void checkRealmAdmin() {
        if (auth == null) {
            throw new NotAuthorizedException("Bearer");
        } else if (auth.getToken().getRealmAccess() == null || !auth.getToken().getRealmAccess().isUserInRole("admin")) {
            throw new ForbiddenException("Does not have realm admin role");
        }
    }

}
