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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.MLDSATestSupport;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.jwk.ThumbprintUtils;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.concurrent.atomic.AtomicInteger;


public class MLDSAKeyGeneratorTest extends TestCase {


	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
	private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);


	public void testRejectUnsupportedAlgorithm() {

		try {
			new MLDSAKeyGenerator(JWSAlgorithm.RS256);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWS algorithm must be ML-DSA", e.getMessage());
		}
	}


	public void testRejectAlgorithmOverrideMismatch() {

		try {
			new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65).algorithm(JWSAlgorithm.ML_DSA_44);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The JWS algorithm must match the ML-DSA key algorithm", e.getMessage());
		}
	}


	public void testGenMinimal()
		throws JOSEException {

		for (JWSAlgorithm algorithm : MLDSATestSupport.ALGORITHMS) {
			MLDSAKey mldsaJWK = new MLDSAKeyGenerator(algorithm).generate();

			assertTrue(mldsaJWK.size() > 0);
			assertEquals(algorithm, mldsaJWK.getAlgorithm());
			assertNull(mldsaJWK.getKeyUse());
			assertNull(mldsaJWK.getKeyOperations());
			assertNull(mldsaJWK.getKeyID());
			assertNull(mldsaJWK.getExpirationTime());
			assertNull(mldsaJWK.getNotBeforeTime());
			assertNull(mldsaJWK.getIssueTime());
			assertNull(mldsaJWK.getKeyStore());
		}
	}


	public void testWithBouncyCastleProvider()
		throws JOSEException {

		MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65)
			.provider(MLDSATestSupport.provider())
			.generate();

		assertTrue(mldsaJWK.size() > 0);
		assertEquals(JWSAlgorithm.ML_DSA_65, mldsaJWK.getAlgorithm());
	}


	public void testWithSecureRandom()
		throws JOSEException {

		final AtomicInteger nextBytesCalls = new AtomicInteger();

		MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65)
			.secureRandom(new SecureRandom() {
				@Override
				public void nextBytes(final byte[] bytes) {
					super.nextBytes(bytes);
					nextBytesCalls.incrementAndGet();
				}
			})
			.generate();

		assertTrue(mldsaJWK.size() > 0);
		assertTrue(nextBytesCalls.get() > 0);
	}


	public void testGenWithParams_explicitKeyID()
		throws JOSEException {

		MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.keyID("1")
			.generate();

		assertEquals(JWSAlgorithm.ML_DSA_65, mldsaJWK.getAlgorithm());
		assertEquals(KeyUse.SIGNATURE, mldsaJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), mldsaJWK.getKeyOperations());
		assertEquals("1", mldsaJWK.getKeyID());
		assertNull(mldsaJWK.getKeyStore());
	}


	public void testGenWithParams_thumbprintKeyID()
		throws JOSEException {

		MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.keyIDFromThumbprint(true)
			.generate();

		assertEquals(JWSAlgorithm.ML_DSA_65, mldsaJWK.getAlgorithm());
		assertEquals(KeyUse.SIGNATURE, mldsaJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), mldsaJWK.getKeyOperations());
		assertEquals(ThumbprintUtils.compute(mldsaJWK).toString(), mldsaJWK.getKeyID());
		assertNull(mldsaJWK.getKeyStore());
	}


	public void testGenWithTimestamps()
		throws JOSEException {

		MLDSAKey mldsaJWK = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65)
			.keyUse(KeyUse.SIGNATURE)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.generate();

		assertEquals(EXP, mldsaJWK.getExpirationTime());
		assertEquals(NBF, mldsaJWK.getNotBeforeTime());
		assertEquals(IAT, mldsaJWK.getIssueTime());
	}
}
