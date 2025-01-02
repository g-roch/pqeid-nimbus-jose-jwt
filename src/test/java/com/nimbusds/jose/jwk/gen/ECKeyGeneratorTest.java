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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


public class ECKeyGeneratorTest extends TestCase {
	
	
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
	private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);
	
	
	public void testGenMinimal()
		throws JOSEException  {
		
		for (Curve curve: Arrays.asList(Curve.P_256, Curve.P_384, Curve.P_521)) {
			
			ECKey ecJWK = new ECKeyGenerator(curve)
				.generate();
			
			assertEquals(curve, ecJWK.getCurve());
			
			assertNull(ecJWK.getKeyUse());
			assertNull(ecJWK.getKeyOperations());
			assertNull(ecJWK.getAlgorithm());
			assertNull(ecJWK.getKeyID());
			assertNull(ecJWK.getExpirationTime());
			assertNull(ecJWK.getNotBeforeTime());
			assertNull(ecJWK.getIssueTime());
			assertNull(ecJWK.getKeyStore());
		}
	}
	
	
	public void testWithBouncyCastleProvider()
		throws JOSEException  {
		
		for (Curve curve: Arrays.asList(Curve.P_256, Curve.P_384, Curve.P_521, Curve.SECP256K1)) {
			
			ECKey ecJWK = new ECKeyGenerator(curve)
				.provider(BouncyCastleProviderSingleton.getInstance())
				.generate();
			
			assertEquals(curve, ecJWK.getCurve());
		}
	}
	
	
	public void testWithSecureRandom()
		throws JOSEException {
		
		final AtomicInteger nextBytesCalls = new AtomicInteger();
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.secureRandom(new SecureRandom() {
				@Override
				public void nextBytes(byte[] bytes) {
					assertEquals(40, bytes.length);
					super.nextBytes(bytes);
					nextBytesCalls.incrementAndGet();
				}
			})
			.generate();
		
		assertEquals(256, ecJWK.size());
		assertEquals(1, nextBytesCalls.get());
	}


	// The x, y, d values that are generated should all be distinct
	public void testDistinctness()
		throws JOSEException  {

		Set<Base64URL> values = new HashSet<>();

		ECKeyGenerator gen = new ECKeyGenerator(Curve.P_256);

		for (int i=0; i<100; i++) {

			ECKey k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
			assertTrue(values.add(k.getY()));
		}

		gen = new ECKeyGenerator(Curve.P_384);

		for (int i=0; i<100; i++) {

			ECKey k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
			assertTrue(values.add(k.getY()));
		}

		gen = new ECKeyGenerator(Curve.P_521);

		for (int i=0; i<100; i++) {

			ECKey k = gen.generate();
			assertTrue(values.add(k.getD()));
			assertTrue(values.add(k.getX()));
			assertTrue(values.add(k.getY()));
		}
	}
	
	
	public void testGenWithParams_explicitKeyID()
		throws JOSEException  {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.ES256)
			.keyID("1")
			.generate();
		
		assertEquals(Curve.P_256, ecJWK.getCurve());
		
		assertEquals(KeyUse.SIGNATURE, ecJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), ecJWK.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, ecJWK.getAlgorithm());
		assertEquals("1", ecJWK.getKeyID());
		assertNull(ecJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_thumbprintKeyID()
		throws JOSEException  {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyUse(KeyUse.SIGNATURE)
			.keyOperations(Collections.singleton(KeyOperation.SIGN))
			.algorithm(JWSAlgorithm.ES256)
			.keyIDFromThumbprint(true)
			.generate();
		
		assertEquals(Curve.P_256, ecJWK.getCurve());
		
		assertEquals(KeyUse.SIGNATURE, ecJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.SIGN), ecJWK.getKeyOperations());
		assertEquals(JWSAlgorithm.ES256, ecJWK.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(ecJWK).toString(), ecJWK.getKeyID());
		assertNull(ecJWK.getKeyStore());
	}
	
	
	public void testGenWithTimestamps() throws JOSEException {
		
		ECKey ecJWK = new ECKeyGenerator(Curve.P_256)
			.keyUse(KeyUse.SIGNATURE)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.generate();
		
		assertEquals(EXP, ecJWK.getExpirationTime());
		assertEquals(NBF, ecJWK.getNotBeforeTime());
		assertEquals(IAT, ecJWK.getIssueTime());
	}


	// Ed25519 and X25519 are not allowed in EC keys.
	// See OctetKeyPair instead.
	public void testGenInvalidCurves() {

		try {
			new ECKeyGenerator(Curve.Ed25519).generate();
			fail();
		} catch (JOSEException e) {
			// Passed
			assertEquals("ECParameterSpec or ECGenParameterSpec required for EC", e.getMessage());
		}

		try {
			new ECKeyGenerator(Curve.X25519).generate();
			fail();

		} catch (JOSEException e) {
			// Passed
			assertEquals("ECParameterSpec or ECGenParameterSpec required for EC", e.getMessage());
		}
	}
}
