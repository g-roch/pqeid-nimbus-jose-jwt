package com.nimbusds.jose.crypto.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;

import java.security.Provider;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * PQEID: base for composite (PQ/T hybrid) ML-DSA JWS signers and verifiers
 * (draft-ietf-jose-pq-composite-sigs-04).
 *
 * <p>No cryptography here: BouncyCastle's LAMPS composite signature implementation does the work
 * (proven to match the JOSE draft, my_learning_guide.md sections 23.5 and 24.3). This class only
 * maps JOSE algorithm names to JCA names and enforces the algorithm checks.
 */
public abstract class CompositeProvider extends BaseJWSProvider {

    /** The supported composite JWS algorithms. Add the higher-assurance profile here. */
    public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;

    /** JOSE name to BouncyCastle JCA signature name. */
    private static final Map<JWSAlgorithm, String> JCA_NAMES =
            Map.of(JWSAlgorithm.ML_DSA_65_ES256, "MLDSA65-ECDSA-P256-SHA512");

    static {
        Set<JWSAlgorithm> algs = new LinkedHashSet<>();
        algs.add(JWSAlgorithm.ML_DSA_65_ES256);
        SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
    }

    protected CompositeProvider() {
        super(SUPPORTED_ALGORITHMS);
    }

    /** The BouncyCastle JCA signature name for a JOSE composite algorithm. */
    protected static String jcaName(final JWSAlgorithm alg) {
        return JCA_NAMES.get(alg);
    }

    /** The configured JCA provider, else BouncyCastle (which implements the composites). */
    protected Provider provider() {
        Provider p = getJCAContext().getProvider();
        return p != null ? p : BouncyCastleProviderSingleton.getInstance();
    }

    /**
     * Rejects unsupported algorithms and any mismatch between the JWS header {@code alg} and the
     * key's algorithm (prevents algorithm confusion, as MLDSASigner/MLDSAVerifier do).
     */
    protected void ensureAlgorithm(final JWSAlgorithm headerAlg, final JWSAlgorithm keyAlg)
            throws JOSEException {
        if (!supportedJWSAlgorithms().contains(headerAlg)) {
            throw new JOSEException(
                    AlgorithmSupportMessage.unsupportedJWSAlgorithm(headerAlg, supportedJWSAlgorithms()));
        }
        if (!headerAlg.equals(keyAlg)) {
            throw new JOSEException(String.format(
                    "Composite JWS algorithm mismatch: header=%s key=%s", headerAlg, keyAlg));
        }
    }
}
