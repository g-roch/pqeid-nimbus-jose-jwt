package com.nimbusds.jose.crypto;

import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.CompositeProvider;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.util.Base64URL;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;
import java.util.Set;

/**
 * PQEID: JWS verifier for composite PQ/T hybrid ML-DSA algorithms (e.g. ML-DSA-65-ES256,
 * draft-ietf-jose-pq-composite-sigs-04). A signature is valid only if BOTH component
 * signatures verify (enforced by BouncyCastle's composite implementation; a stripped or
 * mixed signature is rejected).
 */
public class CompositeVerifier extends CompositeProvider implements JWSVerifier, CriticalHeaderParamsAware {

    private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();

    private final JWSAlgorithm keyAlg;
    private final PublicKey publicKey;

    /**
     * @param key a composite key (its public part is used).
     */
    public CompositeVerifier(final CompositeMLDSAKey key) throws JOSEException {
        this((JWSAlgorithm) Objects.requireNonNull(key, "key").getAlgorithm(), key.toPublicKey());
    }

    /**
     * For a JCA composite public key (e.g. from {@code DefaultJWSVerifierFactory}).
     *
     * @param alg       the composite JWS algorithm the key is for.
     * @param publicKey a BouncyCastle composite public key.
     */
    public CompositeVerifier(final JWSAlgorithm alg, final PublicKey publicKey) {
        if (!SUPPORTED_ALGORITHMS.contains(alg)) {
            throw new IllegalArgumentException("Unsupported composite algorithm: " + alg);
        }
        this.keyAlg = alg;
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
    }

    @Override
    public Set<String> getProcessedCriticalHeaderParams() {
        return critPolicy.getProcessedCriticalHeaderParams();
    }

    @Override
    public Set<String> getDeferredCriticalHeaderParams() {
        return critPolicy.getDeferredCriticalHeaderParams();
    }

    @Override
    public boolean verify(final JWSHeader header, final byte[] signingInput, final Base64URL signature)
            throws JOSEException {
        ensureAlgorithm(header.getAlgorithm(), keyAlg);
        if (!critPolicy.headerPasses(header)) {
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(jcaName(keyAlg), provider());
            verifier.initVerify(publicKey);
            verifier.update(signingInput);
            return verifier.verify(signature.decode());
        } catch (InvalidKeyException e) {
            throw new JOSEException("Invalid composite public key: " + e.getMessage(), e);
        } catch (SignatureException e) {
            return false;   // malformed signature (e.g. truncated or stripped): rejected
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new JOSEException(e.getMessage(), e);
        }
    }
}
