/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
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

package com.nimbusds.jose.proc;


import java.net.URL;
import java.util.Arrays;
import java.util.LinkedHashMap;

import static net.jadler.Jadler.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.MLDSATestSupport;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.MLDSAKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.util.JSONObjectUtils;

public class JWSAlgorithmFamilyJWSKeySelectorTest {
	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}

	@Test
	public void testForRSAFamily() throws Exception {
		RSAKey one = new RSAKeyGenerator(2048)
				.keyID("one").keyUse(KeyUse.SIGNATURE).generate();
		JWKSet jwks = new JWKSet(one);
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.RSA, new ImmutableJWKSet<>(jwks));
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		for (JWSAlgorithm alg: JWSAlgorithm.Family.RSA) {
			jwsHeader = new JWSHeader.Builder(alg).keyID("one").build();
			assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		}
	}

	@Test
	public void testForRSAFamily_matchKeysWithUndefinedUse() throws Exception {
		RSAKey one = new RSAKeyGenerator(2048)
				.keyID("one").generate();
		JWKSet jwks = new JWKSet(one);
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.RSA, new ImmutableJWKSet<>(jwks));
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.ES256);
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		for (JWSAlgorithm alg: JWSAlgorithm.Family.RSA) {
			jwsHeader = new JWSHeader.Builder(alg).keyID("one").build();
			assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		}
	}

	@Test
	public void testForECFamily() throws Exception {
		ECKey one = new ECKeyGenerator(Curve.P_521)
				.keyID("one").keyUse(KeyUse.SIGNATURE).generate();
		JWKSet jwks = new JWKSet(one);
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.EC, new ImmutableJWKSet<>(jwks));
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		for (JWSAlgorithm alg: JWSAlgorithm.Family.EC) {
			jwsHeader = new JWSHeader.Builder(alg).keyID("one").build();
			assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		}
	}

	@Test
	public void testForMLFamily() throws Exception {
		MLDSAKey one = new MLDSAKeyGenerator(JWSAlgorithm.ML_DSA_65)
				.keyID("one").keyUse(KeyUse.SIGNATURE).generate().toPublicJWK();
		JWKSet jwks = new JWKSet(one);
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.ML, new ImmutableJWKSet<>(jwks));
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.RS256);
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		for (JWSAlgorithm alg: JWSAlgorithm.Family.ML) {
			jwsHeader = new JWSHeader.Builder(alg).keyID("one").build();
			if (JWSAlgorithm.ML_DSA_65.equals(alg)) {
				assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
				assertEquals(one.toPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
			} else {
				assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());
			}
		}
	}

	@Test
	public void testForSignature() throws Exception {
		ECKey one = new ECKeyGenerator(Curve.P_521)
				.keyID("one").keyUse(KeyUse.SIGNATURE).generate();
		RSAKey two = new RSAKeyGenerator(2048)
				.keyID("two").keyUse(KeyUse.SIGNATURE).generate();
		JWKSet jwks = new JWKSet(Arrays.asList(one, (JWK) two));
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				new JWSAlgorithmFamilyJWSKeySelector<>(JWSAlgorithm.Family.SIGNATURE, new ImmutableJWKSet<>(jwks));
		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("two").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(two.toRSAPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));

		jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("one").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(one.toECPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
	}

	@Test
	public void testFromJWKSetURL() throws Exception {
		ECKey one = new ECKeyGenerator(Curve.P_521)
				.keyID("one").keyUse(KeyUse.SIGNATURE).generate().toPublicJWK();
		RSAKey two = new RSAKeyGenerator(2048)
				.keyID("two").keyUse(KeyUse.SIGNATURE).generate().toPublicJWK();
		JWKSet jwks = new JWKSet(Arrays.asList(one, (JWK) two));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
		onRequest()
				.havingMethodEqualTo("GET")
				.havingPathEqualTo("/jwks.json")
				.respond()
				.withStatus(200)
				.withHeader("Content-Type", "application/json")
				.withBody(JSONObjectUtils.toJSONString(jwks.toJSONObject(true)));

		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(jwkSetURL);

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("two").build();
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("one").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(one.toECPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
	}

	@Test
	public void testFromJWKSource() throws Exception {
		ECKey one = new ECKeyGenerator(Curve.P_521)
				.keyID("one").keyUse(KeyUse.SIGNATURE).generate().toPublicJWK();
		RSAKey two = new RSAKeyGenerator(2048)
				.keyID("two").keyUse(KeyUse.SIGNATURE).generate().toPublicJWK();
		JWKSet jwks = new JWKSet(Arrays.asList(one, (JWK) two));
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(new ImmutableJWKSet<>(jwks));

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("two").build();
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("one").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(one.toECPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
	}

	@Test
	public void testFromJWKSource_matchKeysWithUndefinedUse() throws Exception {
		ECKey one = new ECKeyGenerator(Curve.P_521)
				.keyID("one").generate().toPublicJWK();
		RSAKey two = new RSAKeyGenerator(2048)
				.keyID("two").generate().toPublicJWK();
		JWKSet jwks = new JWKSet(Arrays.asList(one, (JWK) two));
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(new ImmutableJWKSet<>(jwks));

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("two").build();
		assertTrue(selector.selectJWSKeys(jwsHeader, null).isEmpty());

		jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("one").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(one.toECPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
	}

	@Test
	public void testFromJWKSource_forML() throws Exception {
		MLDSAKey one = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65)).toPublicJWK();
		one = new MLDSAKey.Builder(one)
			.keyID("one")
			.keyUse(KeyUse.SIGNATURE)
			.build();
		JWKSet jwks = new JWKSet(one);
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
				JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(new ImmutableJWKSet<>(jwks));

		assertTrue(selector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("one").build(), null).isEmpty());
		assertTrue(selector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_44).keyID("one").build(), null).isEmpty());

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).keyID("one").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(one.toPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
	}

	@Test
	public void testFromJWKSource_ignoresUnsupportedAKPBeforeEC() throws Exception {
		ECKey ecKey = new ECKeyGenerator(Curve.P_521)
			.keyID("one").keyUse(KeyUse.SIGNATURE).generate().toPublicJWK();
		JWKSet jwks = new JWKSet(Arrays.asList(new UnsupportedAKPJWK("unsupported"), (JWK)ecKey));
		JWSAlgorithmFamilyJWSKeySelector<SecurityContext> selector =
			JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(new ImmutableJWKSet<>(jwks));

		JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.ES512).keyID("one").build();
		assertEquals(1, selector.selectJWSKeys(jwsHeader, null).size());
		assertEquals(ecKey.toECPublicKey(), selector.selectJWSKeys(jwsHeader, null).get(0));
	}

	@Test
	public void testFromJWKSource_rejectsUnsupportedAKPOnly() throws Exception {
		JWKSet jwks = new JWKSet(new UnsupportedAKPJWK("unsupported"));

		try {
			JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(new ImmutableJWKSet<>(jwks));
			fail();
		} catch (KeySourceException e) {
			assertEquals("Couldn't retrieve JWKs", e.getMessage());
		}
	}


	private static final class UnsupportedAKPJWK extends JWK {

		private static final long serialVersionUID = 1L;


		private UnsupportedAKPJWK(final String keyID) {

			super(KeyType.AKP, KeyUse.SIGNATURE, null, JWSAlgorithm.parse("FN-DSA-512"), keyID, null, null, null, null, null);
		}


		@Override
		public boolean isPrivate() {

			return false;
		}

		@Override
		public LinkedHashMap<String, ?> getRequiredParams() {

			LinkedHashMap<String, Object> requiredParams = new LinkedHashMap<>();
			requiredParams.put("kty", KeyType.AKP.getValue());
			requiredParams.put("alg", getAlgorithm().getName());
			return requiredParams;
		}


		@Override
		public JWK toPublicJWK() {

			return this;
		}


		@Override
		public int size() {

			return 1;
		}


		@Override
		public JWK toRevokedJWK(final KeyRevocation keyRevocation) {

			return this;
		}
	}
}
