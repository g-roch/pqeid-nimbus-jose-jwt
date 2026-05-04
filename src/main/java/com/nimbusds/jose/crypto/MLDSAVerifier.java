/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2026, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.crypto;


import com.nimbusds.jose.ByteArrayJWSInput;
import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSInput;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.MLDSA;
import com.nimbusds.jose.crypto.impl.MLDSAProvider;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Set;


/**
 * ML-DSA verifier of {@link com.nimbusds.jose.JWSObject JWS objects}.
 * Expects a public {@link MLDSAKey}.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_44}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_65}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_87}
 * </ul>
 *
 * @version 2026-05-04
 */
@ThreadSafe
public class MLDSAVerifier extends MLDSAProvider implements JWSVerifier, CriticalHeaderParamsAware {


	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	private final MLDSAKey publicKey;


	/**
	 * Creates a new ML-DSA verifier.
	 *
	 * @param publicKey The public ML-DSA key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key is invalid.
	 */
	public MLDSAVerifier(final PublicKey publicKey)
		throws JOSEException {

		this(publicKey, null);
	}


	/**
	 * Creates a new ML-DSA verifier.
	 *
	 * @param publicKey      The public ML-DSA key. Must not be
	 *                       {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws JOSEException If the key is invalid.
	 */
	public MLDSAVerifier(final PublicKey publicKey, final Set<String> defCritHeaders)
		throws JOSEException {

		this(toMLDSAKey(publicKey), defCritHeaders);
	}


	/**
	 * Creates a new ML-DSA verifier.
	 *
	 * @param publicKey The public ML-DSA key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key is invalid.
	 */
	public MLDSAVerifier(final MLDSAKey publicKey)
		throws JOSEException {

		this(publicKey, null);
	}


	/**
	 * Creates a new ML-DSA verifier.
	 *
	 * @param publicKey      The public ML-DSA key. Must not be
	 *                       {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws JOSEException If the key is invalid.
	 */
	public MLDSAVerifier(final MLDSAKey publicKey, final Set<String> defCritHeaders)
		throws JOSEException {

		if (publicKey == null) {
			throw new IllegalArgumentException("The ML-DSA public key must not be null");
		}

		this.publicKey = publicKey.toPublicJWK();
		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	/**
	 * Returns the public key.
	 *
	 * @return The ML-DSA public key.
	 */
	public MLDSAKey getPublicKey() {

		return publicKey;
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

		return verify(header, new ByteArrayJWSInput(signingInput), signature);
	}


	@Override
	public boolean verify(final JWSHeader header, final JWSInput jwsInput, final Base64URL signature)
		throws JOSEException {

		final JWSAlgorithm alg = header.getAlgorithm();

		if (! supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(
				AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}

		if (! critPolicy.headerPasses(header)) {
			return false;
		}

		final JWSAlgorithm keyAlg = (JWSAlgorithm)publicKey.getAlgorithm();
		if (! keyAlg.equals(alg)) {
			throw new JOSEException(
				String.format(
					"ML-DSA JWS algorithm mismatch: header=%s key=%s",
					alg.getName(),
					keyAlg.getName()
				)
			);
		}

		try {
			final Signature verifier = MLDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
			verifier.initVerify(publicKey.toMLDSAPublicKey(getJCAContext().getProvider()));
			jwsInput.apply(verifier);
			return verifier.verify(signature.decode());

		} catch (InvalidKeyException e) {
			throw new JOSEException("Invalid ML-DSA public key: " + e.getMessage(), e);
		} catch (SignatureException e) {
			return false;
		} catch (RuntimeException e) {
			throw new JOSEException(e.getMessage(), e);
		}
	}


	private static MLDSAKey toMLDSAKey(final PublicKey publicKey)
		throws JOSEException {

		try {
			return new MLDSAKey(publicKey);
		} catch (IllegalArgumentException e) {
			throw new JOSEException("Invalid ML-DSA public key: " + e.getMessage(), e);
		}
	}
}
