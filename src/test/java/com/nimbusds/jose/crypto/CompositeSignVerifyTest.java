package com.nimbusds.jose.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import junit.framework.TestCase;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;

/**
 * PQEID: composite ML-DSA-65-ES256 (draft-ietf-jose-pq-composite-sigs-04).
 */
public class CompositeSignVerifyTest extends TestCase {

    private static final int MLDSA65_SIG_LEN = 3309;

    private Map<String, Object> vector;
    private CompositeMLDSAKey key;   // private + public, from the vector's JWK
    private JWSObject officialJws;

     @Override
    protected void setUp() throws Exception {
        String path = "/composite-sigs/ML-DSA-65-ES256.json";
        try (InputStream in = getClass().getResourceAsStream(path)) {
            vector = JSONObjectUtils.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        key = (CompositeMLDSAKey) JWK.parse(JSONObjectUtils.getJSONObject(vector, "jwk"));
        officialJws = JWSObject.parse(JSONObjectUtils.getString(vector, "jws"));
    }

    public void testParsedJwkIsCompositePrivateKey() {
        assertEquals(JWSAlgorithm.ML_DSA_65_ES256, key.getAlgorithm());
        assertTrue(key.isPrivate());
        assertFalse(key.toPublicJWK().isPrivate());
    }

    public void testJwkJsonRoundTrip() throws Exception {
        Map<String, Object> original = JSONObjectUtils.getJSONObject(vector, "jwk");
        Map<String, Object> again = key.toJSONObject();
        for (String member : new String[]{"kty", "alg", "kid", "pub", "priv"}) {
            assertEquals(member, original.get(member), again.get(member));
        }
    }

    public void testOfficialVectorVerifies() throws Exception {
        assertEquals(JWSAlgorithm.ML_DSA_65_ES256, officialJws.getHeader().getAlgorithm());
        assertTrue(officialJws.verify(new CompositeVerifier(key.toPublicJWK())));
    }

    public void testFactoryProvidesCompositeVerifier() throws Exception {
        JWSVerifier v = new DefaultJWSVerifierFactory()
                .createJWSVerifier(officialJws.getHeader(), key.toPublicKey());
        assertTrue(officialJws.verify(v));
    }

    public void testSignThenVerifyRoundTrip() throws Exception {
        JWSObject jws = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65_ES256).keyID(key.getKeyID()).build(),
                new Payload("PQEID round trip"));
        jws.sign(new CompositeSigner(key));
        JWSObject parsed = JWSObject.parse(jws.serialize());
        assertTrue(parsed.verify(new CompositeVerifier(key.toPublicJWK())));
    }

    public void testTamperedMldsaHalfRejected() throws Exception {
        assertTrue(rejected(flip(officialSig(), 100)));
    }

    public void testTamperedEcdsaHalfRejected() throws Exception {
        assertTrue(rejected(flip(officialSig(), MLDSA65_SIG_LEN + 10)));
    }

    public void testMldsaHalfAloneRejected() throws Exception {
        assertTrue(rejected(Arrays.copyOf(officialSig(), MLDSA65_SIG_LEN)));   // ECDSA half stripped
    }

    public void testHalvesFromDifferentMessagesRejected() throws Exception {
        JWSObject other = new JWSObject(new JWSHeader(JWSAlgorithm.ML_DSA_65_ES256), new Payload("other"));
        other.sign(new CompositeSigner(key));
        byte[] otherSig = other.getSignature().decode();
        byte[] mlHalf = Arrays.copyOf(officialSig(), MLDSA65_SIG_LEN);
        byte[] ecHalf = Arrays.copyOfRange(otherSig, MLDSA65_SIG_LEN, otherSig.length);
        byte[] mixed = Arrays.copyOf(mlHalf, mlHalf.length + ecHalf.length);
        System.arraycopy(ecHalf, 0, mixed, mlHalf.length, ecHalf.length);
        assertTrue(rejected(mixed));
    }

    public void testHeaderAlgMismatchRejected() {
        JWSHeader wrong = new JWSHeader(JWSAlgorithm.ML_DSA_65);   // algorithm confusion attempt
        try {
            new CompositeVerifier(key.toPublicJWK())
                    .verify(wrong, officialJws.getSigningInput(), officialJws.getSignature());
            fail("expected JOSEException");
        } catch (JOSEException expected) {
            // ok
        }
    }

    private byte[] officialSig() {
        return officialJws.getSignature().decode();
    }

    private static byte[] flip(byte[] sig, int index) {
        byte[] copy = sig.clone();
        copy[index] ^= 1;
        return copy;
    }

    /** A signature is rejected if verify() returns false OR throws. Both are safe outcomes. */
    private boolean rejected(byte[] sig) {
        try {
            return !new CompositeVerifier(key.toPublicJWK())
                    .verify(officialJws.getHeader(), officialJws.getSigningInput(), Base64URL.encode(sig));
        } catch (JOSEException e) {
            return true;
        }
    }
}