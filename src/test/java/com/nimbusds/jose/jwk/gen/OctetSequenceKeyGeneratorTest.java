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
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.ThumbprintUtils;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;


public class OctetSequenceKeyGeneratorTest extends TestCase {
	
	
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
	private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);
	
	
	public void testMinKeySize() {
		
		assertEquals(112, OctetSequenceKeyGenerator.MIN_KEY_SIZE_BITS);
		
		try {
			new OctetSequenceKeyGenerator(OctetSequenceKeyGenerator.MIN_KEY_SIZE_BITS - 1);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The key size must be at least 112 bits", e.getMessage());
		}
	}
	
	
	public void testMod8() {
		
		for (int n: Arrays.asList(1, 2, 3, 4, 5, 6, 7)) {
			
			try {
				new OctetSequenceKeyGenerator(112 + n);
				fail();
			} catch (IllegalArgumentException e) {
				assertEquals("The key size in bits must be divisible by 8", e.getMessage());
			}
		}
	}
	
	
	public void testGenMinimal()
		throws JOSEException  {
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.generate();
		
		assertEquals(256, octJWK.size());
		
		assertNull(octJWK.getKeyUse());
		assertNull(octJWK.getKeyOperations());
		assertNull(octJWK.getAlgorithm());
		assertNull(octJWK.getKeyID());
		assertNull(octJWK.getExpirationTime());
		assertNull(octJWK.getNotBeforeTime());
		assertNull(octJWK.getIssueTime());
		assertNull(octJWK.getKeyStore());
	}
	
	
	public void testWithSecureRandom()
		throws JOSEException {
		
		final AtomicInteger nextBytesCalls = new AtomicInteger();
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.secureRandom(new SecureRandom() {
				@Override
				public void nextBytes(byte[] bytes) {
					assertEquals(256 / 8, bytes.length);
					super.nextBytes(bytes);
					nextBytesCalls.incrementAndGet();
				}
			})
			.generate();
		
		assertEquals(256, octJWK.size());
		assertEquals(1, nextBytesCalls.get());
	}
	
	
	public void testGenWithParams_explicitKeyID()
		throws JOSEException  {
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.keyUse(KeyUse.ENCRYPTION)
			.keyOperations(Collections.singleton(KeyOperation.ENCRYPT))
			.algorithm(JWEAlgorithm.DIR)
			.keyID("1")
			.generate();
		
		assertEquals(256, octJWK.size());
		
		assertEquals(KeyUse.ENCRYPTION, octJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.ENCRYPT), octJWK.getKeyOperations());
		assertEquals(JWEAlgorithm.DIR, octJWK.getAlgorithm());
		assertEquals("1", octJWK.getKeyID());
		assertNull(octJWK.getKeyStore());
	}
	
	
	public void testGenWithParams_thumbprintKeyID()
		throws JOSEException  {
		
		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(256)
			.keyUse(KeyUse.ENCRYPTION)
			.keyOperations(Collections.singleton(KeyOperation.ENCRYPT))
			.algorithm(JWEAlgorithm.DIR)
			.keyIDFromThumbprint(true)
			.generate();
		
		assertEquals(256, octJWK.size());
		
		assertEquals(KeyUse.ENCRYPTION, octJWK.getKeyUse());
		assertEquals(Collections.singleton(KeyOperation.ENCRYPT), octJWK.getKeyOperations());
		assertEquals(JWEAlgorithm.DIR, octJWK.getAlgorithm());
		assertEquals(ThumbprintUtils.compute(octJWK).toString(), octJWK.getKeyID());
		assertNull(octJWK.getKeyStore());
	}
	

	// The keys that are generated should all be distinct
	public void testDistinctness()
		throws JOSEException  {

		Set<Base64URL> keys = new HashSet<>();

		OctetSequenceKeyGenerator gen = new OctetSequenceKeyGenerator(112);

		for (int i=0; i<1000; i++) {

			OctetSequenceKey k = gen.generate();
			assertTrue(keys.add(k.getKeyValue()));
		}
	}


	public void testGenWithTimestamps() throws JOSEException {

		OctetSequenceKey octJWK = new OctetSequenceKeyGenerator(128)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.generate();

		assertEquals(EXP, octJWK.getExpirationTime());
		assertEquals(NBF, octJWK.getNotBeforeTime());
		assertEquals(IAT, octJWK.getIssueTime());
	}
}
