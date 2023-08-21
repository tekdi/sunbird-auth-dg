package org.sunbird.keycloak.otplogin;

import org.jboss.logging.Logger;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class SMSService {

    private static final Logger logger = Logger.getLogger(SMSService.class);

    void sendSMS(String mobileNumber, String otp) {
        String message = "Dear User, your OTP is " + otp + ". Msg from your senderId";
        System.err.println(message);
        try {
            Date mydate = new Date(System.currentTimeMillis());
            String data = "";
            data += "method=SendMessage";
            data += "&send_to=91" + URLEncoder.encode(mobileNumber, "UTF-8"); // a valid 10 digit phone no.
            data += "&msg=" + URLEncoder.encode(message, String.valueOf(StandardCharsets.UTF_8)); //put message here
            data += "&msg_type=TEXT"; // Can by "FLASH" or
            data += "&userid=your loginId"; // your loginId
            data += "&auth_scheme=plain";
            data += "&password=your password"; // your password
            data += "&v=1.1";
            data += "&format=text";
            URL url = new URL("http://enterprise.smsgupshup.com/GatewayAPI/rest?" + data);
            logger.info("sending message: " + url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setDoInput(true);
            conn.setUseCaches(false);
            conn.connect();
            BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            StringBuffer buffer = new StringBuffer();
            while ((line = rd.readLine()) != null) {
                buffer.append(line).append("\n");
            }
            System.out.println(buffer.toString());
            rd.close();
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
