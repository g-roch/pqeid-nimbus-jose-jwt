package com.nimbusds.jose.crypto;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.impl.CompositeProvider;
import com.nimbusds.jose.jwk.CompositeMLDSAKey;
import com.nimbusds.jose.util.Base64URL;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;

/**
 * PQEID: JWS signer for composite PQ/T hybrid ML-DSA algorithms (e.g. ML-DSA-65-ES256,
 * draft-ietf-jose-pq-composite-sigs-04). Both component signatures are produced by
 * BouncyCastle over the same domain-separated message representative.
 */
public class CompositeSigner extends CompositeProvider implements JWSSigner {

    private final JWSAlgorithm keyAlg;
    private final PrivateKey privateKey;
    private final CompositeMLDSAKey key;

    /**
     * @param key a composite key that includes the private part ({@code priv}).
     */
    public CompositeSigner(final CompositeMLDSAKey key) throws JOSEException {
        if (key == null || !key.isPrivate()) {
            throw new IllegalArgumentException("A private composite ML-DSA key is required");
        }
        this.keyAlg = (JWSAlgorithm) key.getAlgorithm();
        this.privateKey = key.toPrivateKey();
         this.key = key;
    }

    @Override
    public Base64URL sign(final JWSHeader header, final byte[] signingInput) throws JOSEException {
        ensureAlgorithm(header.getAlgorithm(), keyAlg);
        try {
            Signature signer = Signature.getInstance(jcaName(keyAlg), provider());
            SecureRandom random = getJCAContext().getSecureRandom();
            if (random != null) {
                signer.initSign(privateKey, random);
            } else {
                signer.initSign(privateKey);
            }
            signer.update(signingInput);
            return Base64URL.encode(signer.sign());
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new JOSEException("Composite signing failed: " + e.getMessage(), e);
        }
    }

    /** The composite key of this signer (mirrors {@code MLDSASigner.getPrivateKey()}). */
    public CompositeMLDSAKey getPrivateKey() {
        return key;
    }
}
