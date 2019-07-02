package de.g10f.keycloak.rest;

import org.keycloak.models.*;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.admin.AdminRoot;
import org.keycloak.services.validation.Validation;
import org.keycloak.storage.ReadOnlyException;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.Properties;

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

    @Path("{id}")
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    public void resetTOTP(final @PathParam("id") String id, CredentialRepresentation totp) {
        checkRealmAdmin();
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(id, realm);
        if (totp == null || totp.getValue() == null || !CredentialRepresentation.TOTP.equals(totp.getType())) {
            throw new org.jboss.resteasy.spi.BadRequestException("No TOTP provided");
        }
        if (Validation.isBlank(totp.getValue())) {
            throw new org.jboss.resteasy.spi.BadRequestException("Empty TOTP secret not allowed");
        }
        UserCredentialModel cred = UserCredentialModel.totp(totp.getValue());
        try {
            session.userCredentialManager().updateCredential(realm, user, cred);
        } catch (IllegalStateException ise) {
            throw new org.jboss.resteasy.spi.BadRequestException("Resetting to N old passwords is not allowed.");
        } catch (ReadOnlyException mre) {
            throw new org.jboss.resteasy.spi.BadRequestException("Can't reset password as account is read only");
        } catch (ModelException e) {
            Properties messages = AdminRoot.getMessages(session, realm, null);
            throw new ErrorResponseException(e.getMessage(), MessageFormat.format(messages.getProperty(e.getMessage(), e.getMessage()), e.getParameters()),
                    Response.Status.BAD_REQUEST);
        }
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
