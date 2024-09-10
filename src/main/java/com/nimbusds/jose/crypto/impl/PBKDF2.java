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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.IntegerUtils;
import com.nimbusds.jose.util.StandardCharset;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;


/**
 * Password-Based Key Derivation Function 2 (PBKDF2) utilities.
 *
 * @author Brian Campbell
 * @author Pere Bueno Yerbes
 * @author Vladimir Dzhuvinov
 * @version 2024-09-10
 */
public class PBKDF2 {
	
	
	/**
	 * The minimum salt length (8 bytes).
	 */
	public static final int MIN_SALT_LENGTH = 8;


	/**
	 * Zero byte array of length one.
	 */
	static final byte[] ZERO_BYTE = { 0 };// value of (long) Math.pow(2, 32) - 1;
	
	
	/**
	 * Value of {@code (long) Math.pow(2, 32) - 1;}
	 */
	static final long MAX_DERIVED_KEY_LENGTH = 4294967295L;
	
	
	/**
	 * Formats the specified cryptographic salt for use in PBKDF2.
	 *
	 * <pre>
	 * UTF8(JWE-alg) || 0x00 || Salt Input
	 * </pre>
	 *
	 * @param alg  The JWE algorithm. Must not be {@code null}.
	 * @param salt The cryptographic salt. Must be at least 8 bytes long.
	 *
	 * @return The formatted salt for use in PBKDF2.
	 *
	 * @throws JOSEException If formatting failed.
	 */
	public static byte[] formatSalt(final JWEAlgorithm alg, final byte[] salt)
		throws JOSEException {

		byte[] algBytes = alg.toString().getBytes(StandardCharset.UTF_8);
		
		if (salt == null) {
			throw new JOSEException("The salt must not be null");
		}
		
		if (salt.length < MIN_SALT_LENGTH) {
			throw new JOSEException("The salt must be at least " + MIN_SALT_LENGTH + " bytes long");
		}

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			out.write(algBytes);
			out.write(ZERO_BYTE);
			out.write(salt);
		} catch (IOException e) {
			throw new JOSEException(e.getMessage(), e);
		}

		return out.toByteArray();
	}


	/**
	 * Derives a PBKDF2 key from the specified password and parameters.
	 *
	 * @param password       The password. Must not be {@code null}.
	 * @param formattedSalt  The formatted cryptographic salt. Must not be
	 *                       {@code null}.
	 * @param iterationCount The iteration count. Must be a positive
	 *                       integer.
	 * @param prfParams      The Pseudo-Random Function (PRF) parameters.
	 *                       Must not be {@code null}.
	 * @param jcaProvider    The JCA provider, {@code null} if not
	 *                       specified.
	 *
	 * @return The derived secret key (with "AES" algorithm).
	 *
	 * @throws JOSEException If the key derivation failed.
	 */
	public static SecretKey deriveKey(final byte[] password,
					  final byte[] formattedSalt,
					  final int iterationCount,
					  final PRFParams prfParams,
					  final Provider jcaProvider)
		throws JOSEException {
		
		if (formattedSalt == null) {
			throw new JOSEException("The formatted salt must not be null");
		}
		
		if (iterationCount < 1) {
			throw new JOSEException("The iteration count must be greater than 0");
		}
		int keyLengthInBits =  ByteUtils.bitLength(prfParams.getDerivedKeyByteLength());
		PBEKeySpec spec = new PBEKeySpec(new String(password, StandardCharsets.UTF_8).toCharArray(), formattedSalt, iterationCount, keyLengthInBits);
		try {
			final SecretKeyFactory skf;
			if (jcaProvider != null) {
				skf = SecretKeyFactory.getInstance("PBKDF2With" + prfParams.getMACAlgorithm(), jcaProvider);
			} else {
				skf = SecretKeyFactory.getInstance("PBKDF2With" + prfParams.getMACAlgorithm());
			}
			return new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");
		} catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
			throw new JOSEException(ex.getLocalizedMessage(), ex);
		}
	}


	/**
	 * Block extraction iteration.
	 *
	 * @param formattedSalt  The formatted salt. Must not be {@code null}.
	 * @param iterationCount The iteration count. Must be a positive
	 *                       integer.
	 * @param blockIndex     The block index.
	 * @param prf            The pseudo-random function (HMAC). Must not be
	 *                       {@code null}.
	 *
	 * @return The block.
	 *
	 * @throws JOSEException If the block extraction failed.
	 */
	static byte[] extractBlock(final byte[] formattedSalt, final int iterationCount, final int blockIndex, final Mac prf)
		throws JOSEException {
		
		if (formattedSalt == null) {
			throw new JOSEException("The formatted salt must not be null");
		}
		
		if (iterationCount < 1) {
			throw new JOSEException("The iteration count must be greater than 0");
		}

		byte[] currentU;
		byte[] lastU = null;
		byte[] xorU = null;

		for (int i = 1; i <= iterationCount; i++)
		{
			byte[] inputBytes;
			if (i == 1)
			{
				inputBytes = ByteUtils.concat(formattedSalt, IntegerUtils.toBytes(blockIndex));
				currentU = prf.doFinal(inputBytes);
				xorU = currentU;
			}
			else
			{
				currentU = prf.doFinal(lastU);
				for (int j = 0; j < currentU.length; j++)
				{
					xorU[j] = (byte) (currentU[j] ^ xorU[j]);
				}
			}

			lastU = currentU;
		}
		return xorU;
	}


	/**
	 * Prevents public instantiation.
	 */
	private PBKDF2() {}
}
