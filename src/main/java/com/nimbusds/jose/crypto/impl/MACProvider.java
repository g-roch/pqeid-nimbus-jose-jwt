/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2023, Connect2id Ltd and contributors.
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
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.StandardCharset;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 * 
 * @author Vladimir Dzhuvinov
 * @author Ulrich Winter
 * @version 2024-10-28
 */
public abstract class MACProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the MAC provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWSAlgorithm.HS256);
		algs.add(JWSAlgorithm.HS384);
		algs.add(JWSAlgorithm.HS512);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Returns the compatible JWS HMAC algorithms for the specified secret
	 * length.
	 *
	 * @param secretLength The secret length in bits. Must not be negative.
	 *
	 * @return The compatible HMAC algorithms, empty set if the secret
	 *         length is too short for any algorithm.
	 */
	public static Set<JWSAlgorithm> getCompatibleAlgorithms(final int secretLength) {

		Set<JWSAlgorithm> hmacAlgs = new LinkedHashSet<>();

		if (secretLength >= 256)
			hmacAlgs.add(JWSAlgorithm.HS256);

		if (secretLength >= 384)
			hmacAlgs.add(JWSAlgorithm.HS384);

		if (secretLength >= 512)
			hmacAlgs.add(JWSAlgorithm.HS512);

		return Collections.unmodifiableSet(hmacAlgs);
	}


	/**
	 * Returns the minimal required secret length for the specified HMAC
	 * JWS algorithm.
	 *
	 * @param alg The HMAC JWS algorithm. Must be
	 *            {@link #SUPPORTED_ALGORITHMS supported} and not
	 *            {@code null}.
	 *
	 * @return The minimal required secret length, in bits.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static int getMinRequiredSecretLength(final JWSAlgorithm alg)
		throws JOSEException {

		if (JWSAlgorithm.HS256.equals(alg)) {
			return 256;
		} else if (JWSAlgorithm.HS384.equals(alg)) {
			return 384;
		} else if (JWSAlgorithm.HS512.equals(alg)) {
			return 512;
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg,
				SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * Gets the matching Java Cryptography Architecture (JCA) algorithm 
	 * name for the specified HMAC-based JSON Web Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return The matching JCA algorithm name.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	protected static String getJCAAlgorithmName(final JWSAlgorithm alg)
		throws JOSEException {

		if (alg.equals(JWSAlgorithm.HS256)) {
			return "HMACSHA256";
		} else if (alg.equals(JWSAlgorithm.HS384)) {
			return "HMACSHA384";
		} else if (alg.equals(JWSAlgorithm.HS512)) {
			return "HMACSHA512";
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(
				alg,
				SUPPORTED_ALGORITHMS));
		}
	}


	/**
	 * The secret, {@code null} if specified as {@link SecretKey}.
	 */
	private final byte[] secret;


	/**
	 * The secret key, {@code null} if specified as byte array.
	 */
	private final SecretKey secretKey;


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param secret The secret. Must be at least 256 bits long and not
	 *               {@code null}.
	 *
	 * @throws KeyLengthException If the secret length is shorter than the
	 *                            minimum 256-bit requirement.
	 */
	protected MACProvider(final byte[] secret)
		throws KeyLengthException {

		super(getCompatibleAlgorithms(ByteUtils.bitLength(secret.length)));

		if (ByteUtils.bitLength(secret) < 256) {
			// First minimum check. The sign and verify methods
			// check whether the secret matches the concrete HMAC
			// algorithm secret length requirement
			throw new KeyLengthException("The secret length must be at least 256 bits");
		}

		this.secret = secret;
		this.secretKey = null;
	}


	/**
	 * Creates a new Message Authentication (MAC) provider.
	 *
	 * @param secretKey The secret key. Must be at least 256 bits long and
	 *                  not {@code null}.S algorithms. Must not be
	 *                  {@code null}.
	 *
	 * @throws KeyLengthException If the secret length is shorter than the
	 *                            minimum 256-bit requirement.
	 */
	protected MACProvider(final SecretKey secretKey)
		throws KeyLengthException {

		super(
			secretKey.getEncoded() != null ?
			// Get the compatible HSxxx algs for the secret key length
			getCompatibleAlgorithms(ByteUtils.bitLength(secretKey.getEncoded()))
			:
			// HSM-based SecretKey will not expose its key material, assume support for all algs
			SUPPORTED_ALGORITHMS
		);

		// An HSM based key will not expose its material and return null
		if (secretKey.getEncoded() != null && ByteUtils.bitLength(secretKey.getEncoded()) < 256) {
			// First minimum check. The sign and verify methods
			// check whether the secret matches the concrete HMAC
			// algorithm secret length requirement
			throw new KeyLengthException("The secret length must be at least 256 bits");
		}

		this.secretKey = secretKey;
		this.secret = null;
	}


	/**
	 * Gets the secret key.
	 *
	 * @return The secret key.
	 */
	public SecretKey getSecretKey() {
		if(this.secretKey != null) {
			return secretKey;
		} else if (secret != null){
			return new SecretKeySpec(secret, "MAC");
		} else {
			throw new IllegalStateException("Unexpected state");
		}
	}


	/**
	 * Gets the secret bytes.
	 *
	 * @return The secret bytes, {@code null} if this provider was
	 *         constructed with a {@link SecretKey} that doesn't expose the
	 *         key material.
	 */
	public byte[] getSecret() {
		if(this.secretKey != null) {
			return secretKey.getEncoded();
		} else if (secret != null){
			return secret;
		} else {
			throw new IllegalStateException("Unexpected state");
		}
	}


	/**
	 * Gets the secret as a UTF-8 encoded string.
	 *
	 * @return The secret as a UTF-8 encoded string, {@code null} if this
	 *         provider was constructed with a {@link SecretKey} that
	 *         doesn't expose the key material.
	 */
	public String getSecretString() {

		byte[] secret = getSecret();

		if (secret == null) {
			return null;
		}

		return new String(secret, StandardCharset.UTF_8);
	}


	/**
	 * Ensures the secret length satisfies the minimum required for the
	 * specified HMAC JWS algorithm.
	 *
	 * @param alg The HMAC JWS algorithm. Must be
	 *            {@link #SUPPORTED_ALGORITHMS supported} and not
	 *            {@code null}.
	 *
	 * @throws JOSEException      If the algorithm is not supported.
	 * @throws KeyLengthException If the secret length is shorter than the
	 *                            minimum required.
	 */
	protected void ensureSecretLengthSatisfiesAlgorithm(final JWSAlgorithm alg)
		throws JOSEException {

		if (getSecret() == null) {
			// Secret not available (HSM)
			return;
		}

		final int minRequiredBitLength = getMinRequiredSecretLength(alg);

		if (ByteUtils.bitLength(getSecret()) < minRequiredBitLength) {
			throw new KeyLengthException("The secret length for " + alg + " must be at least " + minRequiredBitLength + " bits");
		}
	}
}
