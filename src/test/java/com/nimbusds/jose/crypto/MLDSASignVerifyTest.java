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

package com.nimbusds.jose.crypto;


import com.nimbusds.jose.ActionRequiredForJWSCompletionException;
import com.nimbusds.jose.Header;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSSignerOption;
import com.nimbusds.jose.MLDSATestSupport;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jose.crypto.opts.UserAuthenticationRequired;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import junit.framework.TestCase;

import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.nio.charset.StandardCharsets.UTF_8;


public class MLDSASignVerifyTest extends TestCase {


	public void testSignVerify()
		throws Exception {

		for (JWSAlgorithm alg: MLDSATestSupport.ALGORITHMS) {
			MLDSAKey signerKey = new MLDSAKey(MLDSATestSupport.generateKeyPair(alg));
			MLDSAKey verifierKey = (MLDSAKey)signerKey.toPublicJWK();

			MLDSASigner signer = new MLDSASigner(signerKey);
			MLDSAVerifier verifier = new MLDSAVerifier(verifierKey);

			JWSHeader header = new JWSHeader.Builder(alg).build();
			byte[] signingInput = "hello-pqc".getBytes(UTF_8);

			Base64URL signature = signer.sign(header, signingInput);
			assertTrue(verifier.verify(header, signingInput, signature));
		}
	}


	public void testSignVerifyWithParsedDataOnlyKeys()
		throws Exception {

		for (JWSAlgorithm alg: MLDSATestSupport.ALGORITHMS) {
			MLDSAKey original = new MLDSAKey(MLDSATestSupport.generateKeyPair(alg));
			MLDSAKey signerKey = MLDSAKey.parse(original.toJSONObject());
			MLDSAKey verifierKey = MLDSAKey.parse(original.toPublicJWK().toJSONObject());

			JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(alg).build(), new Payload("parsed"));
			jwsObject.sign(new MLDSASigner(signerKey));

			assertTrue(jwsObject.verify(new MLDSAVerifier(verifierKey)));
		}
	}


	public void testSignVerifyWithWrappedJCAKeys()
		throws Exception {

		for (JWSAlgorithm alg: MLDSATestSupport.ALGORITHMS) {
			java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(alg);

			MLDSAKey signerKey = new MLDSAKey(
				MLDSATestSupport.wrappedPrivateKey(keyPair.getPrivate(), "ML-DSA"),
				MLDSATestSupport.wrappedPublicKey(keyPair.getPublic(), "ML-DSA"));
			MLDSAKey verifierKey = new MLDSAKey(
				MLDSATestSupport.wrappedPublicKey(keyPair.getPublic(), "ML-DSA"));

			JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(alg).build(), new Payload("wrapped"));
			jwsObject.sign(new MLDSASigner(signerKey));

			assertTrue(jwsObject.verify(new MLDSAVerifier(verifierKey)));
		}
	}


	public void testSignVerifyWithOpaquePrivateKeyHandleUsingExplicitProvider()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		MLDSAKey signerKey = new MLDSAKey(
			new OpaquePrivateKeyHandle(keyPair.getPrivate(), JWSAlgorithm.ML_DSA_65.getName()),
			keyPair.getPublic());
		MLDSASigner signer = new MLDSASigner(signerKey);
		signer.getJCAContext().setProvider(new OpaqueHandleMLDSA65Provider());

		JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).build(), new Payload("opaque"));
		jwsObject.sign(signer);

		assertTrue(jwsObject.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
	}


	public void testSignVerifyWithPrivateKeyOnlyConstructor()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		MLDSASigner signer = new MLDSASigner(keyPair.getPrivate());

		assertNotNull(signer.getPrivateKey());
		assertEquals(JWSAlgorithm.ML_DSA_65, signer.getPrivateKey().getAlgorithm());

		JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).build(), new Payload("private-only"));
		jwsObject.sign(signer);

		assertTrue(jwsObject.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
	}


	public void testWithRequireUserAuthenticationOption()
		throws Exception {

		KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		Set<JWSSignerOption> opts = new HashSet<JWSSignerOption>();
		opts.add(UserAuthenticationRequired.getInstance());

		for (boolean asJWK : Arrays.asList(true, false)) {
			JWSSigner signer =
				asJWK ?
					new MLDSASigner(new MLDSAKey(keyPair), opts) :
					new MLDSASigner(keyPair.getPrivate(), opts);

			JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.ML_DSA_65), new Payload("Hello, world!"));
			ActionRequiredForJWSCompletionException actionRequired = null;

			try {
				jwsObject.sign(signer);
				fail();
			} catch (ActionRequiredForJWSCompletionException e) {
				actionRequired = e;
			}

			assertEquals(JWSObject.State.UNSIGNED, jwsObject.getState());
			assertNotNull(actionRequired);

			if (actionRequired != null) {
				assertEquals("Authenticate user to complete signing", actionRequired.getMessage());
				assertEquals(UserAuthenticationRequired.getInstance(), actionRequired.getTriggeringOption());
				assertNotNull(actionRequired.getCompletableJWSObjectSigning());
				assertNotNull(actionRequired.getCompletableJWSObjectSigning().getInitializedSignature());
				actionRequired.getCompletableJWSObjectSigning().complete();
			}

			assertEquals(JWSObject.State.SIGNED, jwsObject.getState());
			assertTrue(jwsObject.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
		}
	}


	public void testRejectsPublicOnlySignerConstruction()
		throws Exception {

		MLDSAKey publicOnlyKey = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65).getPublic());

		try {
			new MLDSASigner(publicOnlyKey);
			fail();
		} catch (JOSEException e) {
			assertTrue(e.getMessage().contains("private part"));
		}
	}


	public void testRejectsAlgorithmMismatch()
		throws Exception {

		MLDSAKey signerKey = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65));
		MLDSASigner signer = new MLDSASigner(signerKey);

		try {
			signer.sign(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_44).build(), "x".getBytes(UTF_8));
			fail();
		} catch (JOSEException e) {
			assertTrue(e.getMessage().contains("mismatch"));
		}
	}


	public void testRejectsUnexpectedHeaderAlgorithm()
		throws Exception {

		MLDSASigner signer = new MLDSASigner(new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65)));
		MLDSAVerifier verifier = new MLDSAVerifier(
			new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65).getPublic()));

		try {
			signer.sign(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), "x".getBytes(UTF_8));
			fail();
		} catch (JOSEException e) {
			assertTrue(e.getMessage().contains("Unsupported JWS algorithm"));
		}

		try {
			verifier.verify(
				new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
				"x".getBytes(UTF_8),
				Base64URL.encode("sig".getBytes(UTF_8)));
			fail();
		} catch (JOSEException e) {
			assertTrue(e.getMessage().contains("Unsupported JWS algorithm"));
		}
	}


	public void testReturnsFalseForUnsupportedCriticalHeaders()
		throws Exception {

		java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65)
				.criticalParams(Collections.singleton("custom"))
				.customParam("custom", "value")
				.build(),
			new Payload("crit"));

		jwsObject.sign(new MLDSASigner(new MLDSAKey(keyPair)));
		assertFalse(jwsObject.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
	}


	public void testSupportsDeferredCriticalHeaders()
		throws Exception {

		java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65)
				.criticalParams(Collections.singleton("custom"))
				.customParam("custom", "value")
				.build(),
			new Payload("crit"));

		jwsObject.sign(new MLDSASigner(new MLDSAKey(keyPair)));
		assertTrue(jwsObject.verify(new MLDSAVerifier(
			new MLDSAKey(keyPair.getPublic()),
			Collections.singleton("custom"))));
	}


	public void testExposesSupportedAlgorithmsAndCriticalHeaderParams()
		throws Exception {

		MLDSASigner signer = new MLDSASigner(new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65)));
		MLDSAVerifier verifier = new MLDSAVerifier(
			new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65).getPublic()),
			Collections.singleton("custom"));

		assertEquals(new HashSet<JWSAlgorithm>(MLDSATestSupport.ALGORITHMS), signer.supportedJWSAlgorithms());
		assertEquals(new HashSet<JWSAlgorithm>(MLDSATestSupport.ALGORITHMS), verifier.supportedJWSAlgorithms());
		assertEquals(Collections.singleton(HeaderParameterNames.BASE64_URL_ENCODE_PAYLOAD), verifier.getProcessedCriticalHeaderParams());
		assertEquals(Collections.singleton("custom"), verifier.getDeferredCriticalHeaderParams());
	}


	public void testSupportsB64CriticalHeaderProcessing()
		throws Exception {

		java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65)
				.base64URLEncodePayload(false)
				.criticalParams(Collections.singleton("b64"))
				.build(),
			new Payload("unencoded-payload"));

		jwsObject.sign(new MLDSASigner(new MLDSAKey(keyPair)));
		assertTrue(jwsObject.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
	}


	public void testReturnsFalseForMalformedSignatureBytes()
		throws Exception {

		MLDSAVerifier verifier = new MLDSAVerifier(
			new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65).getPublic()));

		assertFalse(verifier.verify(
			new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).build(),
			"x".getBytes(UTF_8),
			Base64URL.encode(new byte[] {1})));
	}


	public void testCreateViaDefaultFactories()
		throws Exception {

		java.security.Provider provider = MLDSATestSupport.provider();
		java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65);
		MLDSAKey signerKey = new MLDSAKey(keyPair);

		DefaultJWSSignerFactory signerFactory = new DefaultJWSSignerFactory();
		DefaultJWSVerifierFactory verifierFactory = new DefaultJWSVerifierFactory();
		signerFactory.getJCAContext().setProvider(provider);
		verifierFactory.getJCAContext().setProvider(provider);

		JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).build(), new Payload("factory"));
		jwsObject.sign(signerFactory.createJWSSigner(signerKey, JWSAlgorithm.ML_DSA_65));

		assertTrue(jwsObject.verify(verifierFactory.createJWSVerifier(
			new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).build(),
			keyPair.getPublic())));
	}


	public void testParseSerializedJWSWithEmbeddedMLDSAJWK()
		throws Exception {

		MLDSAKey signerKey = new MLDSAKey(MLDSATestSupport.generateKeyPair(JWSAlgorithm.ML_DSA_65));
		JWSObject jwsObject = new JWSObject(
			new JWSHeader.Builder(JWSAlgorithm.ML_DSA_65).jwk(signerKey.toPublicJWK()).build(),
			new Payload("header-jwk"));

		jwsObject.sign(new MLDSASigner(signerKey));

		JWSObject parsed = JWSObject.parse(jwsObject.serialize());
		assertTrue(parsed.getHeader().getJWK() instanceof MLDSAKey);
		assertTrue(parsed.verify(new MLDSAVerifier((MLDSAKey)parsed.getHeader().getJWK())));
	}


	public void testSerializeParseVerifyAcrossAllAlgorithms()
		throws Exception {

		for (JWSAlgorithm alg : MLDSATestSupport.ALGORITHMS) {
			java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(alg);
			MLDSAKey signerKey = new MLDSAKey(keyPair);
			JWSObject jwsObject = new JWSObject(new JWSHeader.Builder(alg).build(), new Payload(Arrays.asList("m", alg.getName()).toString()));

			jwsObject.sign(new MLDSASigner(signerKey));

			JWSObject parsed = JWSObject.parse(jwsObject.serialize());
			assertTrue(parsed.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
		}
	}


	public void testSerializeParseVerifyAcrossAllAlgorithmsWithX509CertChains()
		throws Exception {

		for (JWSAlgorithm alg : MLDSATestSupport.ALGORITHMS) {
			java.security.KeyPair keyPair = MLDSATestSupport.generateKeyPair(alg);
			MLDSAKey signerKey = new MLDSAKey(keyPair);
			List<Base64> availableCertificates = generateRealisticCertificateChainEntries(alg, keyPair);

			for (int chainLength = 1; chainLength <= 3; chainLength++) {
				JWSHeader header = new JWSHeader.Builder(alg)
					.x509CertChain(availableCertificates.subList(0, chainLength))
					.build();
				int headerLength = header.toString().length();

				// Nimbus rejects these specific ML-DSA / x5c combinations because the
				// protected header exceeds the fixed 20k decoded-string parse limit
				// before signature verification is reached.
				// Header.MAX_HEADER_STRING_LENGTH=32_000 would let the hard header-length
				// check pass, but that's a change that would affect more than just the
				// ML-DSA work.
				// ML-DSA keys are much bigger than even ES512 keys, hence the certificates
				// are much bigger. It seems that at least a dozen (rough estimate)
				// ES512 certs fit into a `x5c` header, which is way more than for ML-DSA:
				// 3 for ML-DSA-44, 2 for ML-DSA-65 and 1 for ML-DSA-87.
				boolean skipForHeaderLengthLimit =
						(JWSAlgorithm.ML_DSA_65.equals(alg) && chainLength == 3) ||
						(JWSAlgorithm.ML_DSA_87.equals(alg) && chainLength >= 2);
				if (skipForHeaderLengthLimit) {
					assertTrue(headerLength > Header.MAX_HEADER_STRING_LENGTH);
					continue;
				}

				assertTrue(headerLength <= Header.MAX_HEADER_STRING_LENGTH);

				JWSObject jwsObject = new JWSObject(
					header,
					new Payload(Arrays.asList(
						"x5c",
						alg.getName(),
						Integer.toString(chainLength),
						"cert-chain-header-coverage").toString()));

				jwsObject.sign(new MLDSASigner(signerKey));

				JWSObject parsed = JWSObject.parse(jwsObject.serialize());
				assertEquals(chainLength, parsed.getHeader().getX509CertChain().size());
				assertTrue(parsed.verify(new MLDSAVerifier(new MLDSAKey(keyPair.getPublic()))));
			}
		}
	}


	private static List<Base64> generateRealisticCertificateChainEntries(final JWSAlgorithm alg, final KeyPair keyPair)
		throws Exception {

		List<Base64> certificates = new ArrayList<>(3);

		for (int i = 0; i < 3; i++) {
			certificates.add(Base64.encode(
				MLDSATestSupport.generateSelfSignedCertificateWithExampleExtensions(alg, keyPair).getEncoded()));
		}

		return certificates;
	}


	private static final class OpaquePrivateKeyHandle implements PrivateKey {

		private final PrivateKey delegate;
		private final String algorithm;


		private OpaquePrivateKeyHandle(final PrivateKey delegate, final String algorithm) {

			this.delegate = delegate;
			this.algorithm = algorithm;
		}


		private PrivateKey unwrap() {

			return delegate;
		}


		@Override
		public String getAlgorithm() {

			return algorithm;
		}


		@Override
		public String getFormat() {

			return "PKCS#11";
		}


		@Override
		public byte[] getEncoded() {

			return null;
		}
	}


	public static final class OpaqueHandleMLDSA65SignatureSpi extends SignatureSpi {

		private Signature delegate;


		@Override
		protected void engineInitVerify(final PublicKey publicKey)
			throws InvalidKeyException {

			delegate = newDelegate();
			delegate.initVerify(publicKey);
		}


		@Override
		protected void engineInitSign(final PrivateKey privateKey)
			throws InvalidKeyException {

			delegate = newDelegate();
			delegate.initSign(
				privateKey instanceof OpaquePrivateKeyHandle ?
					((OpaquePrivateKeyHandle)privateKey).unwrap() :
					privateKey);
		}


		@Override
		protected void engineInitSign(final PrivateKey privateKey, final SecureRandom random)
			throws InvalidKeyException {

			engineInitSign(privateKey);
		}


		@Override
		protected void engineUpdate(final byte b)
			throws SignatureException {

			delegate.update(b);
		}


		@Override
		protected void engineUpdate(final byte[] b, final int off, final int len)
			throws SignatureException {

			delegate.update(b, off, len);
		}


		@Override
		protected byte[] engineSign()
			throws SignatureException {

			return delegate.sign();
		}


		@Override
		protected boolean engineVerify(final byte[] sigBytes)
			throws SignatureException {

			return delegate.verify(sigBytes);
		}


		@Override
		protected void engineSetParameter(final AlgorithmParameterSpec params) {
		}


		@Override
		protected AlgorithmParameters engineGetParameters() {

			return null;
		}


		@Override
		@Deprecated
		protected void engineSetParameter(final String param, final Object value) {
		}


		@Override
		@Deprecated
		protected Object engineGetParameter(final String param) {

			return null;
		}


		private static Signature newDelegate()
			throws InvalidKeyException {

			try {
				return Signature.getInstance(JWSAlgorithm.ML_DSA_65.getName(), MLDSATestSupport.provider());
			} catch (Exception e) {
				InvalidKeyException invalidKeyException = new InvalidKeyException(e.getMessage());
				invalidKeyException.initCause(e);
				throw invalidKeyException;
			}
		}
	}


	private static final class OpaqueHandleMLDSA65Provider extends Provider {

		private OpaqueHandleMLDSA65Provider() {

			super("OpaqueMLDSATest", 1.0, "ML-DSA opaque private-key test provider");
			put("Signature." + JWSAlgorithm.ML_DSA_65.getName(), OpaqueHandleMLDSA65SignatureSpi.class.getName());
		}
	}
}
