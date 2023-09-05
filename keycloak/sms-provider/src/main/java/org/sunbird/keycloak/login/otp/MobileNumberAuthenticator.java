package org.sunbird.keycloak.login.otp;


import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.sunbird.keycloak.resetcredential.sms.KeycloakSmsAuthenticatorUtil;
import org.sunbird.keycloak.utils.Constants;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Random;


public class MobileNumberAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(MobileNumberAuthenticator.class);

    private final OtpLoginSmsService smsService = new OtpLoginSmsService();

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("action request");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String type = formData.getFirst(Constants.FORM_TYPE);
        logger.debug("action request type " + type);
        if (type.equals(Constants.LOGIN_FORM)) {
            String mobileNumber = formData.getFirst(Constants.MOBILE_NUMBER);
            List<UserModel> users = context.getSession().users()
                    .searchForUserByUserAttribute(Constants.MOBILE_NUMBER, mobileNumber, context.getSession().getContext().getRealm());
            logger.info("First name: " + users.get(0).getFirstName());
            if (!users.isEmpty()) {
                generateOTP(context, mobileNumber, users);
            } else {
                users = context.getSession().users()
                        .searchForUserByUserAttribute(Constants.MOBILE_NUMBER, mobileNumber, context.getSession().getContext().getRealm());
                if (!users.isEmpty()) {
                    generateOTP(context, mobileNumber, users);
                } else {
                    context.failure(AuthenticationFlowError.INVALID_USER);
                }
            }
        } else if (type.equals(Constants.VERIFY_OTP_FORM)) {
            String sessionKey = context.getAuthenticationSession().getAuthNote(Constants.OTP);
            if (sessionKey != null) {
                String secret = formData.getFirst(Constants.OTP);
                logger.info("code: " + secret);
                if (secret != null) {
                    if (secret.equals(sessionKey)) {
                        //context.getEvent().success();
                        context.success();
                    } else {
                        context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                    }
                } else {
                    context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
                }
            } else {
                context.challenge(context.form().createForm(Constants.OTP_LOGIN_UI));
            }
        }
    }

    private void generateOTP(AuthenticationFlowContext context, String mobileNumber, List<UserModel> users) {
        UserModel user = users.get(0);
        Random rand = new Random();
        String otp = String.format("%04d", rand.nextInt(10000));
        boolean sendStatus = new KeycloakSmsAuthenticatorUtil().sendSmsCode(mobileNumber, otp, context.getAuthenticatorConfig());
        if (sendStatus) {
            context.getAuthenticationSession().setAuthNote(Constants.OTP, otp);
            context.setUser(user);
            context.challenge(context.form().createForm(Constants.OTP_VERIFY_UI));
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        LoginFormsProvider forms = context.form();

        if (formData.size() > 0) forms.setFormData(formData);

        return forms.createForm(Constants.OTP_LOGIN_UI);
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getAttributes().get(Constants.MOBILE_NUMBER) != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
