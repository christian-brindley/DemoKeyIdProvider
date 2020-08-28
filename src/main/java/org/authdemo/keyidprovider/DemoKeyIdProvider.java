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

import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Optional;
import org.forgerock.openam.secrets.KeyStoreKeyIdProvider;
import org.forgerock.json.jose.jwk.KeyUse;


/**
 * KeyStoreKeyIdProvider implementation for ForgeRock AM.
 *
 * Provides rfc7638 compliant key ids built from SHA1 hash of JWK thumbprint
 */

public class DemoKeyIdProvider implements KeyStoreKeyIdProvider {
    @Override
    public String getKeyId(KeyUse keyUse, String alias, PublicKey publicKey, Optional<Certificate> certificate) {

        return ThumbprintUtils.getRfc7638ThumbprintFromKey(publicKey);
    }
}


