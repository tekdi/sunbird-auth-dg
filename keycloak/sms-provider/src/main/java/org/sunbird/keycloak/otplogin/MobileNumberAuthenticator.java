package org.sunbird.keycloak.otplogin;


import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import javax.ws.rs.core.MultivaluedMap;
import java.util.List;

import static org.sunbird.keycloak.otplogin.Constants.*;

public class MobileNumberAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(MobileNumberAuthenticator.class);
    private OtpService otpService = new OtpService();
    private EmailService emailService = new EmailService();
    private SMSService smsService = new SMSService();

    @Override
    public void action(AuthenticationFlowContext context) {
        logger.debug("action request");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String type = formData.getFirst(FORM_TYPE);
        logger.debug("action request type " + type);
        if (type.equals(LOGIN_FORM)) {
            String mobileNumber = formData.getFirst(MOBILE_NUMBER);
            List<UserModel> users = context.getSession().users()
                    .searchForUserByUserAttribute(MOBILE_NUMBER, mobileNumber, context.getSession().getContext().getRealm());
            logger.info("First name: " + users.get(0).getFirstName());
            if (users.size() > 0) {
                generateOTP(context, mobileNumber, users);
            } else {
                users = context.getSession().users()
                        .searchForUserByUserAttribute(EMAIL, mobileNumber, context.getSession().getContext().getRealm());
                if (users.size() > 0) {
                    generateOTP(context, mobileNumber, users);
                } else {
                    context.failure(AuthenticationFlowError.INVALID_USER);
                }
            }
        } else if (type.equals(VERIFY_OTP_FORM)) {
            String sessionKey = context.getAuthenticationSession().getAuthNote(OTP);
            if (sessionKey != null) {
                String secret = formData.getFirst(OTP);
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
                context.challenge(context.form().createForm(MOBILE_LOGIN_UI));
            }
        }
    }

    private void generateOTP(AuthenticationFlowContext context, String mobileNumber, List<UserModel> users) {
        UserModel user = users.get(0);
        String otp = otpService.generateOTP(mobileNumber);
        List<String> mobileNumberNodes = user.getAttributes().get(MOBILE_NUMBER);
        if (!mobileNumberNodes.isEmpty()) {
            logger.debug("Mobile: " + mobileNumberNodes.get(0) + "OTP: " + otp);
            //KeycloakSmsAuthenticatorUtil.sendSmsCode(mobileNumber, otp, context.getAuthenticatorConfig());
            smsService.sendSMS(mobileNumberNodes.get(0), otp);
        }
        context.getAuthenticationSession().setAuthNote(OTP, otp);
        context.setUser(user);
        context.challenge(context.form().createForm(VERIFY_OTP_UI));
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.challenge(context.form().createForm(MOBILE_LOGIN_UI));
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return user.getAttributes().get(MOBILE_NUMBER) != null;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
