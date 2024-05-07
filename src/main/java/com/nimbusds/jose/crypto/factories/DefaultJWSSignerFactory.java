/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2020, Connect2id Ltd.
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

package com.nimbusds.jose.crypto.factories;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.produce.JWSSignerFactory;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A factory to create JWS signers from a JWK instance based on the
 * key type.
 *
 * @author Justin Richer
 * @since 2024-05-07
 */
public class DefaultJWSSignerFactory implements JWSSignerFactory {

	/**
	 * The JCA context.
	 */
	private final JCAContext jcaContext = new JCAContext();

	/**
	 * The supported JWS algorithms.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.addAll(MACSigner.SUPPORTED_ALGORITHMS);
		algs.addAll(RSASSASigner.SUPPORTED_ALGORITHMS);
		algs.addAll(ECDSASigner.SUPPORTED_ALGORITHMS);
		algs.addAll(Ed25519Signer.SUPPORTED_ALGORITHMS);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}

	@Override
	public Set<JWSAlgorithm> supportedJWSAlgorithms() {
		return SUPPORTED_ALGORITHMS;
	}

	@Override
	public JCAContext getJCAContext() {
		return jcaContext;
	}

	@Override
	public JWSSigner createJWSSigner(final JWK key) throws JOSEException {

		if (!key.isPrivate()) { // can't create a signer without the private key
			throw JWKException.expectedPrivate();
		}
		
		if (key.getKeyUse() != null && ! KeyUse.SIGNATURE.equals(key.getKeyUse())) {
			throw new JWKException("The JWK use must be sig (signature) or unspecified");
		}

		JWSSigner signer;

		// base this just on the key type (+ curve) alone without the algorithm check
		if (key instanceof OctetSequenceKey) {
			signer = new MACSigner((OctetSequenceKey)key);
		} else if (key instanceof RSAKey) {
			signer = new RSASSASigner((RSAKey)key);
		} else if (key instanceof ECKey && ECDSASigner.SUPPORTED_CURVES.contains(((ECKey) key).getCurve())) {
			signer = new ECDSASigner((ECKey)key);
		} else if (key instanceof OctetKeyPair && Ed25519Signer.SUPPORTED_CURVES.contains(((OctetKeyPair) key).getCurve())) {
			signer = new Ed25519Signer((OctetKeyPair)key);
		} else {
			throw new JOSEException("Unsupported JWK type and / or curve");
		}

		// Apply JCA context
		signer.getJCAContext().setSecureRandom(jcaContext.getSecureRandom());
		signer.getJCAContext().setProvider(jcaContext.getProvider());

		return signer;
	}

	@Override
	public JWSSigner createJWSSigner(final JWK key, final JWSAlgorithm alg) throws JOSEException {

		if (!key.isPrivate()) { // can't create a signer without the private key
			throw JWKException.expectedPrivate();
		}
		
		if (key.getKeyUse() != null && ! KeyUse.SIGNATURE.equals(key.getKeyUse())) {
			throw new JWKException("The JWK use must be sig (signature) or unspecified");
		}

		JWSSigner signer;


		if (
			MACSigner.SUPPORTED_ALGORITHMS.contains(alg) &&
			key instanceof OctetSequenceKey) {

			signer = new MACSigner((OctetSequenceKey)key);

		} else if (
			RSASSASigner.SUPPORTED_ALGORITHMS.contains(alg) &&
			key instanceof RSAKey) {

			signer = new RSASSASigner((RSAKey)key);

		} else if (
			ECDSASigner.SUPPORTED_ALGORITHMS.contains(alg) &&
			key instanceof ECKey &&
			ECDSASigner.SUPPORTED_CURVES.contains(((ECKey) key).getCurve())) {

			signer = new ECDSASigner((ECKey)key);

		} else if (
			Ed25519Signer.SUPPORTED_ALGORITHMS.contains(alg) &&
			key instanceof OctetKeyPair &&
			Ed25519Signer.SUPPORTED_CURVES.contains(((OctetKeyPair) key).getCurve())) {

			signer = new Ed25519Signer((OctetKeyPair)key);

		} else {
			throw new JOSEException("Unsupported JWK type, JWK curve and / or JWS algorithm");
		}

		// Apply JCA context
		signer.getJCAContext().setSecureRandom(jcaContext.getSecureRandom());
		signer.getJCAContext().setProvider(jcaContext.getProvider());

		return signer;
	}
}
