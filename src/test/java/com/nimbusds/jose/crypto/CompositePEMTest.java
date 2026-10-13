package com.nimbusds.jose.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import junit.framework.TestCase;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.StringWriter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;

/** PQEID: composite keys loaded from PEM (the .env SIGNING_KEY / SDJWT_KEY path). */
public class CompositePEMTest extends TestCase {

    static {
        // BC's composite KeyPairGenerator looks up its component generators by
        // provider name "BC", so BC must be registered (not just passed as an object).
        Security.addProvider(BouncyCastleProviderSingleton.getInstance());
    }

    private static KeyPair generate() throws Exception {
        return KeyPairGenerator.getInstance("MLDSA65-ECDSA-P256-SHA512",
                BouncyCastleProviderSingleton.getInstance()).generateKeyPair();
    }

    private static String pem(Key... keys) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(sw)) {
            for (Key k : keys) w.writeObject(k);
        }
        return sw.toString();
    }

    private static boolean signThenVerify(CompositeMLDSAKey key) throws Exception {
        JWSObject jws = new JWSObject(new JWSHeader(JWSAlgorithm.ML_DSA_65_ES256),
                new Payload("hello"));
        jws.sign(new CompositeSigner(key));
        return JWSObject.parse(jws.serialize()).verify(new CompositeVerifier(key.toPublicJWK()));
    }

    public void testPrivatePlusPublicPemParsesToCompositeKey() throws Exception {
        KeyPair kp = generate();
        JWK jwk = JWK.parseFromPEMEncodedObjects(pem(kp.getPrivate(), kp.getPublic()));
        assertTrue(jwk instanceof CompositeMLDSAKey);
        assertEquals(JWSAlgorithm.ML_DSA_65_ES256, jwk.getAlgorithm());
        assertTrue(jwk.isPrivate());
    }

    public void testPemKeySignsAndVerifies() throws Exception {
        KeyPair kp = generate();
        JWK jwk = JWK.parseFromPEMEncodedObjects(pem(kp.getPrivate(), kp.getPublic()));
        assertTrue(signThenVerify((CompositeMLDSAKey) jwk));
    }

    public void testPublicOnlyPemIsPublicKey() throws Exception {
        JWK jwk = JWK.parseFromPEMEncodedObjects(pem(generate().getPublic()));
        assertTrue(jwk instanceof CompositeMLDSAKey);
        assertFalse(jwk.isPrivate());
    }

    /** Option (b) by design: the public key is not derived from the private key. */
    public void testPrivateOnlyPemRejected() throws Exception {
        String pem = pem(generate().getPrivate());
        try {
            JWK.parseFromPEMEncodedObjects(pem);
            fail("A private-only composite PEM must be rejected");
        } catch (JOSEException expected) {
            // "Missing PEM-encoded public key to construct JWK"
        }
    }

    /** Known residual: a mismatched pair parses, but its signatures never verify. */
    public void testMismatchedPairParsesButDoesNotVerify() throws Exception {
        KeyPair a = generate(), b = generate();
        JWK jwk = JWK.parseFromPEMEncodedObjects(pem(a.getPrivate(), b.getPublic()));
        assertFalse(signThenVerify((CompositeMLDSAKey) jwk));
    }
}