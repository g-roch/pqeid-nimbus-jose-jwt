/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Objects;


/**
 * Elliptic Curve (EC) JSON Web Key (JWK) generator.
 *
 * <p>Supported curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256 P-256}
 *     <li>{@link Curve#SECP256K1 secp256k1}
 *     <li>{@link Curve#P_384 P-384}
 *     <li>{@link Curve#P_521 P-512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Cranford
 * @version 2024-12-15
 */
public class ECKeyGenerator extends JWKGenerator<ECKey> {
	
	
	/**
	 * The curve.
	 */
	private final Curve crv;
	
	
	/**
	 * Creates a new EC JWK generator.
	 *
	 * @param crv The curve. Must not be {@code null}.
	 */
	public ECKeyGenerator(final Curve crv) {
		this.crv = Objects.requireNonNull(crv);
	}
	
	
	@Override
	public ECKey generate()
		throws JOSEException  {
		
		ECParameterSpec ecSpec = crv.toECParameterSpec();
		
		KeyPairGenerator generator;
		try {
			if (keyStore != null) {
				// For PKCS#11
				generator = KeyPairGenerator.getInstance("EC", keyStore.getProvider());
			} else if (provider != null) {
				generator = KeyPairGenerator.getInstance("EC", provider);
			} else {
				generator = KeyPairGenerator.getInstance("EC");
			}
			if (secureRandom != null) {
				generator.initialize(ecSpec, secureRandom);
			} else {
				// The default random gen
				generator.initialize(ecSpec);
			}
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new JOSEException(e.getMessage(), e);
		}
		
		KeyPair kp = generator.generateKeyPair();
		
		ECKey.Builder builder = new ECKey.Builder(crv, (ECPublicKey) kp.getPublic())
			.privateKey(kp.getPrivate())
			.keyUse(use)
			.keyOperations(ops)
			.algorithm(alg)
			.expirationTime(exp)
			.notBeforeTime(nbf)
			.issueTime(iat)
			.keyStore(keyStore);
		
		if (tprKid) {
			builder.keyIDFromThumbprint();
		} else {
			builder.keyID(kid);
		}
		
		return builder.build();
	}
}
