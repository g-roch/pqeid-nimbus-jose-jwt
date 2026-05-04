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

package com.nimbusds.jose.jwk.gen;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.MLDSAKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.util.Objects;


/**
 * ML-DSA JSON Web Key (JWK) generator.
 *
 * <p>Supported algorithms:
 *
 * <ul>
 *     <li>{@link JWSAlgorithm#ML_DSA_44}
 *     <li>{@link JWSAlgorithm#ML_DSA_65}
 *     <li>{@link JWSAlgorithm#ML_DSA_87}
 * </ul>
 *
 * @version 2026-05-04
 */
public class MLDSAKeyGenerator extends JWKGenerator<MLDSAKey> {


	/**
	 * The ML-DSA JWS algorithm.
	 */
	private final JWSAlgorithm algorithm;


	/**
	 * Creates a new ML-DSA JWK generator.
	 *
	 * @param algorithm The ML-DSA JWS algorithm. Must not be
	 *                  {@code null}.
	 */
	public MLDSAKeyGenerator(final JWSAlgorithm algorithm) {

		if (! JWSAlgorithm.Family.ML.contains(Objects.requireNonNull(algorithm))) {
			throw new IllegalArgumentException("The JWS algorithm must be ML-DSA");
		}

		this.algorithm = algorithm;
		this.alg = algorithm;
	}


	@Override
	public MLDSAKeyGenerator algorithm(final Algorithm alg) {

		if (alg != null && ! algorithm.equals(alg)) {
			throw new IllegalArgumentException("The JWS algorithm must match the ML-DSA key algorithm");
		}

		super.algorithm(alg);
		return this;
	}


	@Override
	public MLDSAKey generate()
		throws JOSEException {

		final Provider resolvedProvider = keyStore != null ?
			keyStore.getProvider() :
			provider != null ? provider : BouncyCastleProviderSingleton.getInstance();

		final KeyPairGenerator generator;
		try {
			generator = KeyPairGenerator.getInstance("ML-DSA", resolvedProvider);

			MLDSAParameterSpec parameterSpec = toParameterSpec(algorithm);
			if (secureRandom != null) {
				generator.initialize(parameterSpec, secureRandom);
			} else {
				generator.initialize(parameterSpec);
			}

		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new JOSEException(e.getMessage(), e);
		}

		KeyPair keyPair = generator.generateKeyPair();

		MLDSAKey mldsaKey = new MLDSAKey.Builder(keyPair)
			.keyUse(use)
			.keyOperations(ops)
			.algorithm(algorithm)
			.keyID(kid)
			.expirationTime(exp)
			.notBeforeTime(nbf)
			.issueTime(iat)
			.keyStore(keyStore)
			.build();

		if (tprKid) {
			mldsaKey = new MLDSAKey.Builder(mldsaKey)
				.keyID(mldsaKey.computeThumbprint().toString())
				.build();
		}

		return mldsaKey;
	}


	private static MLDSAParameterSpec toParameterSpec(final JWSAlgorithm algorithm)
		throws JOSEException {

		if (JWSAlgorithm.ML_DSA_44.equals(algorithm)) {
			return MLDSAParameterSpec.ml_dsa_44;
		}

		if (JWSAlgorithm.ML_DSA_65.equals(algorithm)) {
			return MLDSAParameterSpec.ml_dsa_65;
		}

		if (JWSAlgorithm.ML_DSA_87.equals(algorithm)) {
			return MLDSAParameterSpec.ml_dsa_87;
		}

		throw new JOSEException("Unsupported ML-DSA JWS algorithm: " + algorithm);
	}
}
