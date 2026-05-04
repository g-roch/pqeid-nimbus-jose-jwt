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

package com.nimbusds.jose.jwk;


import com.nimbusds.jose.MLDSATestSupport;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;


/**
 * Tests the ML-DSA JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2026-05-04
 */
public class MLDSAKeyTest extends TestCase {


	public void testRoundTripsJWKRepresentations()
		throws Exception {

		for (JWSAlgorithm algorithm : MLDSATestSupport.ALGORITHMS) {
			KeyPair keyPair = MLDSATestSupport.generateKeyPair(algorithm);
			MLDSAKey privateJWK = new MLDSAKey(keyPair);
			MLDSAKey publicJWK = (MLDSAKey) privateJWK.toPublicJWK();

			assertEquals(algorithm, privateJWK.mlDsaJwsAlgorithm());
			assertTrue(privateJWK.isPrivate());
			assertFalse(publicJWK.isPrivate());

			Map<String, Object> privateJSON = privateJWK.toJSONObject();
			assertEquals("AKP", privateJSON.get("kty"));
			assertEquals(algorithm.getName(), privateJSON.get("alg"));
			assertTrue(privateJSON.containsKey("pub"));
			assertTrue(privateJSON.containsKey("priv"));

			Map<String, Object> publicJSON = publicJWK.toJSONObject();
			assertEquals("AKP", publicJSON.get("kty"));
			assertEquals(algorithm.getName(), publicJSON.get("alg"));
			assertTrue(publicJSON.containsKey("pub"));
			assertFalse(publicJSON.containsKey("priv"));

			assertEquals(privateJWK.computeThumbprint(), publicJWK.computeThumbprint());
			assertTrue(privateJWK.size() > 0);

			assertEquals(privateJWK, MLDSAKey.parse(privateJSON));
			assertEquals(publicJWK, MLDSAKey.parse(publicJSON));
			assertEquals(privateJWK, MLDSAKey.parse(privateJWK.toJSONString()));
		}
	}


	public void testPreservesParsedDataOnlyKeyPaths()
		throws Exception {

		Provider provider = MLDSATestSupport.provider();

		for (JWSAlgorithm algorithm : MLDSATestSupport.ALGORITHMS) {
			MLDSAKey original = new MLDSAKey(MLDSATestSupport.generateKeyPair(algorithm));
			MLDSAKey parsedPrivate = MLDSAKey.parse(original.toJSONObject());
			MLDSAKey parsedPublic = MLDSAKey.parse(original.toPublicJWK().toJSONObject());
			KeyRevocation revocation = new KeyRevocation(
				Date.from(Instant.parse("2026-04-01T00:00:00Z")),
				KeyRevocation.Reason.UNSPECIFIED);

			assertTrue(parsedPrivate.size() > 0);
			assertTrue(parsedPublic.size() > 0);
			assertEquals(algorithm.getName(), parsedPrivate.toMLDSAPrivateKey(provider).getAlgorithm());
			assertEquals(algorithm.getName(), parsedPrivate.toMLDSAPublicKey(provider).getAlgorithm());
			assertEquals(algorithm.getName(), parsedPublic.toMLDSAPublicKey(provider).getAlgorithm());

			MLDSAKey revoked = (MLDSAKey) parsedPrivate.toRevokedJWK(revocation);
			assertEquals(revocation, revoked.getKeyRevocation());
			Map<String, Object> revokedJSON = revoked.toJSONObject();
			assertTrue(revokedJSON.containsKey(MLDSAKey.PUBLIC_KEY_PARAMETER));
			assertTrue(revokedJSON.containsKey(MLDSAKey.PRIVATE_KEY_PARAMETER));
		}
	}


	public void testSupportsAsymmetricJWKConversions()
		throws Exception {

		for (JWSAlgorithm algorithm : MLDSATestSupport.ALGORITHMS) {
			KeyPair keyPair = MLDSATestSupport.generateKeyPair(algorithm);
			MLDSAKey key = new MLDSAKey(keyPair);
			MLDSAKey publicKey = new MLDSAKey(keyPair.getPublic());
			MLDSAKey parsed = MLDSAKey.parse(key.toJSONObject());

			assertEquals(keyPair.getPublic(), key.toPublicKey());
			assertEquals(keyPair.getPrivate(), key.toPrivateKey());
			assertEquals(keyPair.getPublic(), key.toKeyPair().getPublic());
			assertEquals(keyPair.getPrivate(), key.toKeyPair().getPrivate());

			assertNull(publicKey.toPrivateKey());
			assertNull(publicKey.toKeyPair().getPrivate());
			assertEquals(algorithm.getName(), parsed.toPublicKey().getAlgorithm());
			assertEquals(algorithm.getName(), parsed.toPrivateKey().getAlgorithm());
		}
	}


	public void testSupportsWrappedNonBouncyCastleKeys()
		throws Exception {

		Provider provider = MLDSATestSupport.provider();

		for (JWSAlgorithm algorithm : MLDSATestSupport.ALGORITHMS) {
			KeyPair keyPair = MLDSATestSupport.generateKeyPair(algorithm);
			PrivateKey wrappedPrivate =
				MLDSATestSupport.wrappedPrivateKey(keyPair.getPrivate(), "ML-DSA");
			PublicKey wrappedPublic =
				MLDSATestSupport.wrappedPublicKey(keyPair.getPublic(), "ML-DSA");
			MLDSAKey privateJWK = new MLDSAKey(wrappedPrivate, wrappedPublic);
			MLDSAKey publicJWK = new MLDSAKey(wrappedPublic);

			assertEquals(algorithm, privateJWK.mlDsaJwsAlgorithm());
			assertEquals(algorithm, publicJWK.mlDsaJwsAlgorithm());
			assertTrue(privateJWK.size() > 0);
			assertTrue(publicJWK.size() > 0);

			Map<String, Object> privateJSON = privateJWK.toJSONObject();
			assertEquals(algorithm.getName(), privateJSON.get("alg"));
			assertTrue(privateJSON.containsKey("pub"));
			assertTrue(privateJSON.containsKey("priv"));

			Map<String, Object> publicJSON = publicJWK.toJSONObject();
			assertEquals(algorithm.getName(), publicJSON.get("alg"));
			assertTrue(publicJSON.containsKey("pub"));
			assertFalse(publicJSON.containsKey("priv"));

			assertEquals(algorithm.getName(), privateJWK.toMLDSAPrivateKey(provider).getAlgorithm());
			assertEquals(algorithm.getName(), publicJWK.toMLDSAPublicKey(provider).getAlgorithm());
		}
	}


	public void testParsesX509Certificate()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		X509Certificate cert = MLDSATestSupport.generateSelfSignedCertificate(JWSAlgorithm.ML_DSA_65, keyPair);

		MLDSAKey mldsaKey = MLDSAKey.parse(cert);

		assertEquals(JWSAlgorithm.ML_DSA_65, mldsaKey.mlDsaJwsAlgorithm());
		assertEquals(1, mldsaKey.getX509CertChain().size());
		assertNotNull(mldsaKey.getX509CertSHA256Thumbprint());
		assertTrue(mldsaKey.matches(cert));
	}


	public void testLoadsFromKeyStore()
		throws Exception {

		KeyStore keyStore = KeyStore.getInstance("BKS", MLDSATestSupport.provider());
		keyStore.load(null, "secret".toCharArray());

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		X509Certificate cert = MLDSATestSupport.generateSelfSignedCertificate(JWSAlgorithm.ML_DSA_65, keyPair);

		keyStore.setKeyEntry("1", keyPair.getPrivate(), "1234".toCharArray(), new Certificate[] {cert});

		MLDSAKey mldsaKey = MLDSAKey.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(mldsaKey);
		assertEquals("1", mldsaKey.getKeyID());
		assertTrue(mldsaKey.isPrivate());
		assertEquals(JWSAlgorithm.ML_DSA_65, mldsaKey.mlDsaJwsAlgorithm());
	}


	public void testRejectsMismatchedPrivateKeyWhenLoadingFromKeyStore()
		throws Exception {

		KeyStore keyStore = KeyStore.getInstance("BKS", MLDSATestSupport.provider());
		keyStore.load(null, "secret".toCharArray());

		KeyPair privateKeyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		KeyPair certificateKeyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		X509Certificate cert = MLDSATestSupport.generateSelfSignedCertificate(JWSAlgorithm.ML_DSA_65, certificateKeyPair);

		keyStore.setKeyEntry("1", privateKeyPair.getPrivate(), "1234".toCharArray(), new Certificate[] {cert});

		JOSEException exception = assertException(JOSEException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				MLDSAKey.load(keyStore, "1", "1234".toCharArray());
			}
		});
		assertTrue(exception.getMessage().contains("doesn't match"));
	}


	public void testParsesLegacyKeyTypeAndOptionalMetadata()
		throws Exception {

		MLDSAKey key = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65));
		Map<String, Object> json = new HashMap<String, Object>(key.toJSONObject());
		KeyRevocation revocation = new KeyRevocation(
			Date.from(Instant.parse("2026-04-02T00:00:00Z")),
			KeyRevocation.Reason.UNSPECIFIED);

		json.put("kty", MLDSAKey.LEGACY_KEY_TYPE.getValue());
		json.put("kid", "kid-1");
		json.put("use", "sig");
		json.put("key_ops", Arrays.asList("sign", "verify"));
		json.put("x5u", "https://example.invalid/cert.pem");
		json.put("x5t", Base64URL.encode("thumbprint".getBytes(UTF_8)).toString());
		json.put("x5t#S256", Base64URL.encode("thumbprint256".getBytes(UTF_8)).toString());
		json.put("exp", Instant.parse("2026-04-03T00:00:00Z").getEpochSecond());
		json.put("nbf", Instant.parse("2026-04-04T00:00:00Z").getEpochSecond());
		json.put("iat", Instant.parse("2026-04-05T00:00:00Z").getEpochSecond());
		json.put("revoked", revocation.toJSONObject());

		MLDSAKey parsed = MLDSAKey.parse(json);

		assertEquals("kid-1", parsed.getKeyID());
		assertEquals(KeyUse.SIGNATURE, parsed.getKeyUse());
		Set<KeyOperation> expectedKeyOps = new HashSet<KeyOperation>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));
		assertEquals(expectedKeyOps, parsed.getKeyOperations());
		assertEquals(URI.create("https://example.invalid/cert.pem"), parsed.getX509CertURL());
		assertEquals(Base64URL.encode("thumbprint".getBytes(UTF_8)).toString(), parsed.toJSONObject().get("x5t"));
		assertEquals(Base64URL.encode("thumbprint256".getBytes(UTF_8)), parsed.getX509CertSHA256Thumbprint());
		assertEquals(Date.from(Instant.parse("2026-04-03T00:00:00Z")), parsed.getExpirationTime());
		assertEquals(Date.from(Instant.parse("2026-04-04T00:00:00Z")), parsed.getNotBeforeTime());
		assertEquals(Date.from(Instant.parse("2026-04-05T00:00:00Z")), parsed.getIssueTime());
		assertEquals(revocation, parsed.getKeyRevocation());
	}


	public void testRejectsUnsupportedKeyTypeOnParse() {

		Map<String, Object> json = new HashMap<String, Object>();
		json.put("kty", "EC");
		json.put("alg", JWSAlgorithm.ML_DSA_65.getName());
		json.put("pub", "AQI");

		ParseException exception = assertException(ParseException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				MLDSAKey.parse(json);
			}
		});
		assertTrue(exception.getMessage().contains("kty"));
	}


	public void testRejectsUnsupportedAlgorithmOnParse() {

		Map<String, Object> json = new HashMap<String, Object>();
		json.put("kty", "AKP");
		json.put("alg", "ML-DSA-999");
		json.put("pub", Base64URL.encode("abc".getBytes(UTF_8)).toString());

		ParseException exception = assertException(ParseException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				MLDSAKey.parse(json);
			}
		});
		assertTrue(exception.getMessage().contains("Unsupported ML-DSA JWS algorithm"));
	}


	public void testRejectsMissingPublicKeyOnParse() {

		Map<String, Object> json = new HashMap<String, Object>();
		json.put("kty", "AKP");
		json.put("alg", JWSAlgorithm.ML_DSA_65.getName());

		ParseException exception = assertException(ParseException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				MLDSAKey.parse(json);
			}
		});
		assertEquals("Missing public key \"pub\" parameter", exception.getMessage());
	}


	public void testTreatsEmptyCertificateChainAsAbsentOnParse()
		throws Exception {

		MLDSAKey key = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65));
		Map<String, Object> json = new HashMap<String, Object>(key.toJSONObject());
		json.put("x5c", Collections.emptyList());

		MLDSAKey parsed = MLDSAKey.parse(json);

		assertNull(parsed.getX509CertChain());
		assertNull(parsed.getParsedX509CertChain());
	}


	public void testRejectsMalformedRevocationOnParse() {

		Map<String, Object> json = new HashMap<String, Object>();
		json.put("kty", "AKP");
		json.put("alg", JWSAlgorithm.ML_DSA_65.getName());
		json.put("pub", Base64URL.encode("abc".getBytes(UTF_8)).toString());
		json.put("revoked", "not-an-object");

		ParseException exception = assertException(ParseException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				MLDSAKey.parse(json);
			}
		});
		assertTrue(exception.getMessage().contains("revoked"));
	}


	public void testRejectsInvalidCertificateChainOnParse() {

		MLDSAKey key = new MLDSAKey(MLDSATestSupport.generateKeyPairUnchecked(JWSAlgorithm.ML_DSA_65));
		Map<String, Object> json = new HashMap<String, Object>(key.toJSONObject());
		json.put("x5c", Collections.singletonList(Base64.encode("not-a-certificate".getBytes(UTF_8)).toString()));

		IllegalArgumentException exception = assertException(IllegalArgumentException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				MLDSAKey.parse(json);
			}
		});
		assertTrue(exception.getMessage().contains("x5c"));
	}


	public void testRejectsMismatchedX509CertificateChain()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		KeyPair otherKeyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		final X509Certificate otherCert = MLDSATestSupport.generateSelfSignedCertificate(JWSAlgorithm.ML_DSA_65, otherKeyPair);
		MLDSAKey key = new MLDSAKey(keyPair);

		assertFalse(key.matches(otherCert));

		IllegalArgumentException exception = assertException(IllegalArgumentException.class, new TestAction() {
			@Override
			public void run() throws Exception {
				new MLDSAKey.Builder(key)
					.x509CertChain(Collections.singletonList(Base64.encode(otherCert.getEncoded())))
					.build();
			}
		});
		assertTrue(exception.getMessage().contains("must match the JWK type and public parameters"));
	}


	public void testRejectsInvalidMlDsaKeyObjects() {

		IllegalArgumentException privateException = assertException(IllegalArgumentException.class, new TestAction() {
			@Override
			public void run() {
				new MLDSAKey(MLDSATestSupport.invalidPrivateKey(), MLDSATestSupport.invalidPublicKey());
			}
		});
		assertTrue(privateException.getMessage().contains("Invalid ML-DSA private key"));

		IllegalArgumentException publicException = assertException(IllegalArgumentException.class, new TestAction() {
			@Override
			public void run() {
				new MLDSAKey(MLDSATestSupport.invalidPublicKey());
			}
		});
		assertTrue(publicException.getMessage().contains("Invalid ML-DSA public key"));
	}


	public void testRejectsMismatchedMlDsaKeyPairAlgorithms()
		throws Exception {

		PrivateKey privateKey = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_44).getPrivate();
		PublicKey publicKey = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65).getPublic();

		IllegalArgumentException exception = assertException(IllegalArgumentException.class, new TestAction() {
			@Override
			public void run() {
				new MLDSAKey(privateKey, publicKey);
			}
		});
		assertTrue(exception.getMessage().contains("algorithm mismatch"));
		assertTrue(exception.getMessage().contains(JWSAlgorithm.ML_DSA_44.getName()));
		assertTrue(exception.getMessage().contains(JWSAlgorithm.ML_DSA_65.getName()));
	}


	public void testRejectsWrappedPublicKeyWithMalformedEncodingWhenExtractingPublicData()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		PublicKey wrappedPublic = MLDSATestSupport.wrappedPublicKey(
			keyPair.getPublic(),
			JWSAlgorithm.ML_DSA_65.getName(),
			new byte[] {1, 2, 3});
		MLDSAKey key = new MLDSAKey(wrappedPublic);

		IllegalStateException exception = assertException(IllegalStateException.class, new TestAction() {
			@Override
			public void run() {
				key.size();
			}
		});
		assertTrue(exception.getMessage().contains("Unable to extract ML-DSA public key bytes"));
	}


	public void testRejectsWrappedPrivateKeyWithMalformedEncodingWhenExtractingPrivateData()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		PrivateKey wrappedPrivate = MLDSATestSupport.wrappedPrivateKey(
			keyPair.getPrivate(),
			JWSAlgorithm.ML_DSA_65.getName(),
			new byte[] {1, 2, 3});
		MLDSAKey key = new MLDSAKey(wrappedPrivate, keyPair.getPublic());

		IllegalStateException exception = assertException(IllegalStateException.class, new TestAction() {
			@Override
			public void run() {
				key.toJSONObject();
			}
		});
		assertTrue(exception.getMessage().contains("Unable to extract ML-DSA private key bytes"));
	}


	public void testUsesDefaultBouncyCastleProviderWhenRehydratingJCAKeys()
		throws Exception {

		MLDSAKey parsed = MLDSAKey.parse(
			new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65)).toJSONObject());

		assertEquals(JWSAlgorithm.ML_DSA_65.getName(), parsed.toMLDSAPublicKey().getAlgorithm());
		assertEquals(JWSAlgorithm.ML_DSA_65.getName(), parsed.toMLDSAPrivateKey().getAlgorithm());
		assertEquals(JWSAlgorithm.ML_DSA_65.getName(), parsed.toMLDSAPublicKey(null).getAlgorithm());
		assertEquals(JWSAlgorithm.ML_DSA_65.getName(), parsed.toMLDSAPrivateKey(null).getAlgorithm());
	}


	public void testExplicitProviderRehydrationDoesNotReuseCachedDefaultProviderKeys()
		throws Exception {

		MLDSAKey parsed = MLDSAKey.parse(
			new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65)).toJSONObject());

		PrivateKey defaultPrivateKey = parsed.toMLDSAPrivateKey();
		PublicKey defaultPublicKey = parsed.toMLDSAPublicKey();

		Provider provider1 = new BouncyCastleProvider();
		Provider provider2 = new BouncyCastleProvider();

		PrivateKey providerPrivateKey1 = parsed.toMLDSAPrivateKey(provider1);
		PublicKey providerPublicKey1 = parsed.toMLDSAPublicKey(provider1);
		PrivateKey providerPrivateKey2 = parsed.toMLDSAPrivateKey(provider2);
		PublicKey providerPublicKey2 = parsed.toMLDSAPublicKey(provider2);

		assertNotSame(defaultPrivateKey, providerPrivateKey1);
		assertNotSame(defaultPublicKey, providerPublicKey1);
		assertNotSame(providerPrivateKey1, providerPrivateKey2);
		assertNotSame(providerPublicKey1, providerPublicKey2);
	}


	public void testMarksKeysAsRevokedOnlyOnce()
		throws Exception {

		MLDSAKey key = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65));
		KeyRevocation revocation = new KeyRevocation(new Date(), KeyRevocation.Reason.UNSPECIFIED);
		final MLDSAKey revoked = (MLDSAKey) key.toRevokedJWK(revocation);

		assertNotNull(revoked.getKeyRevocation());

		IllegalStateException exception = assertException(IllegalStateException.class, new TestAction() {
			@Override
			public void run() {
				revoked.toRevokedJWK(revocation);
			}
		});
		assertTrue(exception.getMessage().contains("Already revoked"));
	}


	private interface TestAction {

		void run() throws Exception;
	}


	private static <T extends Throwable> T assertException(final Class<T> exceptionClass, final TestAction action) {

		try {
			action.run();
		} catch (Throwable e) {
			if (exceptionClass.isInstance(e)) {
				return exceptionClass.cast(e);
			}
			AssertionError assertionError = new AssertionError(
				"Unexpected exception type, expected " + exceptionClass.getName() + " but got " + e.getClass().getName());
			assertionError.initCause(e);
			throw assertionError;
		}

		fail("Expected exception " + exceptionClass.getName());
		return null;
	}
}
