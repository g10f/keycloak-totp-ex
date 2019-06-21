package de.g10f.keycloak.credential;

import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.TimeBasedOTP;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

/**
 * TOTP: Time-based One-time Password Algorithm Based on http://tools.ietf.org/html/draft-mraihi-totp-timebased-06
 *
 * @author <a href="mailto:mail@g10f.de">Gunnar Scherf</a>
 * @since Sep 20, 2010
 */
public class TimeBasedOTPEx extends TimeBasedOTP {
    private static final int[] DIGITS_POWER = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

    public TimeBasedOTPEx(String algorithm, int numberDigits, int timeIntervalInSeconds, int lookAheadWindow) {
        super(algorithm, numberDigits, timeIntervalInSeconds, lookAheadWindow);
    }

    @Override
    public boolean validateTOTP(String token, byte[] secret) {
        // secret is assumed as a base32 encoded string and
        // base32.decode(value) throws an exception if the value has only one or zero chars.
        if (secret.length > 1) {
            return super.validateTOTP(token, secret);
        } else {
            return false;
        }
    }


    /**
     * This method generates an OTP value for the given set of parameters.
     * Distinct to the original keycloak method, the key is Base32 encoded,
     * so that we can store secrets from external sources in the varchar database field,
     * not only byte arrays from ascii chars
     *
     * @param key          the shared secret, Base32 encoded
     * @param counter      a value that reflects a time
     * @param returnDigits number of digits to return
     * @param crypto       the crypto function to use
     * @return A numeric String in base 10 that includes return digits
     * @throws java.security.GeneralSecurityException
     */
    public String generateOTP(String key, String counter, int returnDigits, String crypto) {
        String result = null;
        byte[] hash;

        // Using the counter
        // First 8 bytes are for the movingFactor
        // Complaint with base RFC 4226 (HOTP)
        while (counter.length() < 16)
            counter = "0" + counter;

        // Get the HEX in a Byte[]
        byte[] msg = hexStr2Bytes(counter);

        //byte[] k = key.getBytes(); original source code
        // new
        byte[] k = Base32.decode(key);

        hash = hmac_sha1(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

        int otp = binary % DIGITS_POWER[returnDigits];

        result = Integer.toString(otp);

        while (result.length() < returnDigits) {
            result = "0" + result;
        }
        return result;
    }

    /**
     * This method converts HEX string to Byte[]
     *
     * @param hex the HEX string
     * @return A byte array
     */
    private byte[] hexStr2Bytes(String hex) {
        // Adding one byte to get the right conversion
        // values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i + 1];
        return ret;
    }

    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a Hashed Message Authentication Code with the
     * crypto hash algorithm as a parameter.
     *
     * @param crypto   the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes the bytes to use for the HMAC key
     * @param text     the message or text to be authenticated.
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.InvalidKeyException
     */
    private byte[] hmac_sha1(String crypto, byte[] keyBytes, byte[] text) {
        byte[] value;

        try {
            Mac hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");

            hmac.init(macKey);

            value = hmac.doFinal(text);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return value;
    }

}