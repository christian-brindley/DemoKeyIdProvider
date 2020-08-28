/***************************************************************************
 *                                                                         *
 *  The sample code described herein is provided on an "as is" basis,      *
 *  without warranty of any kind, to the fullest extent permitted by law.  *
 *  ForgeRock does not warrant or guarantee the individual success         *
 *  developers may have in implementing the sample code on their           *
 *  development platforms or in production configurations.                 *
 *                                                                         *
 *  ForgeRock does not warrant, guarantee or make any representations      *
 *  regarding the use, results of use, accuracy, timeliness or             *
 *  completeness of any data or information relating to the sample code.   *
 *                                                                         *
 *  ForgeRock disclaims all warranties, expressed or implied, and in       *
 *  particular, disclaims all warranties of merchantability, and           *
 *  warranties related to the code, or any service or software related     *
 *  thereto.                                                               *
 *                                                                         *
 *  ForgeRock shall not be liable for any direct, indirect or              *
 *  consequential damages or costs of any type arising out of any action   *
 *  taken by you or others related to the sample code.                     *
 *                                                                         *
 ***************************************************************************/

package org.authdemo.keyidprovider;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.SortedMap;
import java.util.TreeMap;
import org.forgerock.json.jose.jws.SupportedEllipticCurve;
import org.forgerock.json.JsonValue;
import java.security.MessageDigest;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.util.Arrays;

public class ThumbprintUtils {
    static String getRfc7638ThumbprintFromKey(PublicKey publicKey){

        String thumbprint = null;

        final SortedMap<String, String> essentialKeys = new TreeMap();


        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            String curve = getCurve(ecPublicKey);
            BigInteger x = ecPublicKey.getW().getAffineX();
            BigInteger y = ecPublicKey.getW().getAffineY();

            essentialKeys.put("kty", "EC");
            essentialKeys.put("crv", curve);
            essentialKeys.put("x", jwkBase64(toByteArrayUnsigned(x)));
            essentialKeys.put("y", jwkBase64(toByteArrayUnsigned(y)));

        } else if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            BigInteger n = rsaPublicKey.getModulus();
            BigInteger e = rsaPublicKey.getPublicExponent();

            essentialKeys.put("kty", "RSA");
            essentialKeys.put("n", jwkBase64(toByteArrayUnsigned(n)));
            essentialKeys.put("e", jwkBase64(toByteArrayUnsigned(e)));

        } else {
            throw new IllegalArgumentException("Public key type not supported.");
        }


        final JsonValue jsonValue = new JsonValue(essentialKeys);

        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-1");

            String macInput = jsonValue.toString().replaceAll("\\s+", "");
            byte[] digest = md.digest(macInput.getBytes(UTF_8));
            thumbprint = jwkBase64(digest);
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Error building digest [" + e + "]");
        }

        return thumbprint;

    }

    /**
     * toByteArrayUnsigned
     * @param bi - input BigInteger
     * @return - unsigned version as byte array
     */
    private static byte[] toByteArrayUnsigned(BigInteger bi) {
        byte[] extractedBytes = bi.toByteArray();
        int skipped = 0;
        boolean skip = true;
        for (byte b : extractedBytes) {
            boolean signByte = b == (byte) 0x00;
            if (skip && signByte) {
                skipped++;
                continue;
            } else if (skip) {
                skip = false;
            }
        }
        extractedBytes = Arrays.copyOfRange(extractedBytes, skipped,
                extractedBytes.length);
        return extractedBytes;
    }

    /**
     * jwkBase64
     * @param input byte array to encode
     * @return Base64 encoded with trailing equals sign(s) removed
     */
    private static String jwkBase64(byte[] input)
    {
        return Base64.getUrlEncoder().encodeToString(input).replaceAll("=","");
    }

    /**
     * Figure out curve from EC public key
     */
    private static String getCurve(ECPublicKey ecPublicKey) {
        String curve = null;

        switch (SupportedEllipticCurve.forKey(ecPublicKey))
        {
            case P256:
                curve = "P-256";
                break;

            case P384:
                curve = "P-384";
                break;

            case P521:
                curve = "P-521";
                break;
        }

        return curve;
    }

}
