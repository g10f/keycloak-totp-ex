import de.g10f.keycloak.credential.TimeBasedOTPEx;
import org.apache.log4j.BasicConfigurator;
import org.junit.Test;
import org.keycloak.models.OTPPolicy;

public class TOTPTest {
    @Test
    public void testgenerateOTP() throws Exception {
        // Test that random ASCII strings at least don't throw any exception
        BasicConfigurator.configure();

        OTPPolicy policy = OTPPolicy.DEFAULT_POLICY;
        TimeBasedOTPEx timeBasedOTPEx = new TimeBasedOTPEx(policy.getAlgorithm(), policy.getDigits(),
                policy.getPeriod(), policy.getLookAheadWindow());
        for (int i = 1; i < 100; i++) {
            String secret = TimeBasedOTPEx.generateSecret(i);
            for (int j = 0; j < 100; j++) {
                String token = TimeBasedOTPEx.generateSecret(j);
                timeBasedOTPEx.validateTOTP(token, secret.getBytes());
            }
        }
    }
}
