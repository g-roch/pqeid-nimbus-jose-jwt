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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;


/**
 * ML-DSA functions and utilities.
 *
 * @version 2026-05-04
 */
public class MLDSA {


	/**
	 * Returns a signer and verifier for the specified ML-DSA based JSON
	 * Web Algorithm (JWA).
	 *
	 * @param alg      The JSON Web Algorithm (JWA). Must be supported and
	 *                 not {@code null}.
	 * @param provider The JCA provider, {@code null} to use
	 *                 BouncyCastle.
	 *
	 * @return A signer and verifier instance.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static Signature getSignerAndVerifier(final JWSAlgorithm alg, final Provider provider)
		throws JOSEException {

		if (! MLDSAProvider.SUPPORTED_ALGORITHMS.contains(alg)) {
			throw new JOSEException(
				AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, MLDSAProvider.SUPPORTED_ALGORITHMS));
		}

		Provider jcaProvider = provider != null ? provider : BouncyCastleProviderSingleton.getInstance();

		try {
			return Signature.getInstance(alg.getName(), jcaProvider);
		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException(e.getMessage(), e);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private MLDSA() {
	}
}
