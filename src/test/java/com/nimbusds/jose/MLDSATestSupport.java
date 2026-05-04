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

package com.nimbusds.jose;


import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;


public final class MLDSATestSupport {


	public static final List<JWSAlgorithm> ALGORITHMS = Collections.unmodifiableList(
		Arrays.asList(JWSAlgorithm.ML_DSA_44, JWSAlgorithm.ML_DSA_65, JWSAlgorithm.ML_DSA_87));


	private MLDSATestSupport() {
	}


	public static Provider provider() {

		return BouncyCastleProviderSingleton.getInstance();
	}


	public static KeyPair generateKeyPair(final JWSAlgorithm algorithm)
		throws Exception {

		KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm.getName(), provider());
		return generator.generateKeyPair();
	}


	public static KeyPair generateKeyPairUnchecked(final JWSAlgorithm algorithm) {

		try {
			return generateKeyPair(algorithm);
		} catch (Exception e) {
			throw new AssertionError("Unable to generate ML-DSA key pair for test", e);
		}
	}


	public static KeyPair generateRsaKeyPair()
		throws Exception {

		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		return generator.generateKeyPair();
	}


	public static X509Certificate generateSelfSignedCertificate(final JWSAlgorithm algorithm, final KeyPair keyPair)
		throws Exception {

		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date notBefore = new Date(now.getTime() - 1000L);
		Date notAfter = new Date(now.getTime() + 365L * 24L * 60L * 60L * 1000L);
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			notBefore,
			notAfter,
			issuer,
			keyPair.getPublic()
		);

		X509CertificateHolder certHolder = certBuilder.build(
			new JcaContentSignerBuilder(algorithm.getName())
				.setProvider(provider())
				.build(keyPair.getPrivate())
		);

		return (X509Certificate)CertificateFactory.getInstance("X.509", provider())
			.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
	}


	public static X509Certificate generateSelfSignedCertificateWithExampleExtensions(final JWSAlgorithm algorithm, final KeyPair keyPair)
		throws Exception {

		String algorithmName = algorithm.getName().toLowerCase(Locale.ROOT).replace('-', '_');
		X500Name issuer = new X500Name(
			"CN=" + algorithm.getName() +
				" signing leaf,O=Connect2id test PKI,OU=PQ signatures,L=Brussels,ST=Brussels,C=BE");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date notBefore = new Date(now.getTime() - 1000L);
		Date notAfter = new Date(now.getTime() + 365L * 24L * 60L * 60L * 1000L);
		JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			notBefore,
			notAfter,
			issuer,
			keyPair.getPublic()
		);
		JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();

		certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
		certBuilder.addExtension(
			Extension.keyUsage,
			true,
			new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
		certBuilder.addExtension(
			Extension.extendedKeyUsage,
			false,
			new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth}));
		certBuilder.addExtension(
			Extension.subjectKeyIdentifier,
			false,
			extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
		certBuilder.addExtension(
			Extension.authorityKeyIdentifier,
			false,
			extensionUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));
		certBuilder.addExtension(
			Extension.subjectAlternativeName,
			false,
			new GeneralNames(new GeneralName[] {
				new GeneralName(GeneralName.dNSName, algorithmName + ".signing.example.org"),
				new GeneralName(GeneralName.uniformResourceIdentifier, "https://keys.example.org/" + algorithmName + "/jwk-set.json"),
				new GeneralName(GeneralName.rfc822Name, algorithmName + "@example.org")
			}));

		X509CertificateHolder certHolder = certBuilder.build(
			new JcaContentSignerBuilder(algorithm.getName())
				.setProvider(provider())
				.build(keyPair.getPrivate())
		);

		return (X509Certificate)CertificateFactory.getInstance("X.509", provider())
			.generateCertificate(new ByteArrayInputStream(certHolder.getEncoded()));
	}


	public static String toPEM(final Object object)
		throws IOException {

		StringWriter writer = new StringWriter();

		try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
			pemWriter.writeObject(object);
		}

		return writer.toString();
	}


	public static PublicKey invalidPublicKey() {

		return new InvalidPublicKey();
	}


	public static PrivateKey invalidPrivateKey() {

		return new InvalidPrivateKey();
	}


	public static PublicKey wrappedPublicKey(final PublicKey delegate, final String algorithm) {

		return wrappedPublicKey(delegate, algorithm, delegate.getEncoded());
	}


	public static PublicKey wrappedPublicKey(final PublicKey delegate, final String algorithm, final byte[] encoded) {

		return new DelegatingPublicKey(delegate.getFormat(), algorithm, encoded);
	}


	public static PrivateKey wrappedPrivateKey(final PrivateKey delegate, final String algorithm) {

		return wrappedPrivateKey(delegate, algorithm, delegate.getEncoded());
	}


	public static PrivateKey wrappedPrivateKey(final PrivateKey delegate, final String algorithm, final byte[] encoded) {

		return new DelegatingPrivateKey(delegate.getFormat(), algorithm, encoded);
	}


	private abstract static class InvalidKey implements Key {

		@Override
		public String getAlgorithm() {

			return "ML-DSA";
		}


		@Override
		public String getFormat() {

			return "RAW";
		}


		@Override
		public byte[] getEncoded() {

			return new byte[] {1, 2, 3};
		}
	}


	private static final class InvalidPublicKey extends InvalidKey implements PublicKey {
	}


	private static final class InvalidPrivateKey extends InvalidKey implements PrivateKey {
	}


	private abstract static class DelegatingKey implements Key {

		private final String format;
		private final String algorithm;
		private final byte[] encoded;


		private DelegatingKey(final String format, final String algorithm, final byte[] encoded) {

			this.format = format;
			this.algorithm = algorithm;
			this.encoded = encoded != null ? Arrays.copyOf(encoded, encoded.length) : null;
		}


		@Override
		public String getAlgorithm() {

			return algorithm;
		}


		@Override
		public String getFormat() {

			return format;
		}


		@Override
		public byte[] getEncoded() {

			return encoded != null ? Arrays.copyOf(encoded, encoded.length) : null;
		}
	}


	private static final class DelegatingPublicKey extends DelegatingKey implements PublicKey {

		private DelegatingPublicKey(final String format, final String algorithm, final byte[] encoded) {

			super(format, algorithm, encoded);
		}
	}


	private static final class DelegatingPrivateKey extends DelegatingKey implements PrivateKey {

		private DelegatingPrivateKey(final String format, final String algorithm, final byte[] encoded) {

			super(format, algorithm, encoded);
		}
	}
}
