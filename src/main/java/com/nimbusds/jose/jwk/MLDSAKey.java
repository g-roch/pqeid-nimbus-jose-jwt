/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2024, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.impl.MLDSA;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.bc.BCObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;


/**
 * ML-DSA {@link JWK} implementation for signing and verification flows that
 * need to transport ML-DSA public keys as JOSE JWKs.
 *
 * <p>The current JWK JSON representation uses the more generic
 * {@code kty=AKP} shape with {@code pub}/{@code priv} members and keeps
 * parsing compatibility with the earlier internal {@code kty=ML-DSA} form
 * that existed before the extraction into this standalone module.
 *
 * @version 2026-05-04
 */
public final class MLDSAKey extends AKPJWK {


	private static final long serialVersionUID = 1L;


	/**
	 * The key operations for private signing keys.
	 */
	public static final Set<KeyOperation> KEY_OPS_SIGN = Collections.singleton(KeyOperation.SIGN);


	/**
	 * The key operations for public verification keys.
	 */
	public static final Set<KeyOperation> KEY_OPS_VERIFY = Collections.singleton(KeyOperation.VERIFY);


	static final KeyType LEGACY_KEY_TYPE = new KeyType("ML-DSA", Requirement.OPTIONAL);
	static final String PUBLIC_KEY_PARAMETER = AKPJWK.PUBLIC_KEY_PARAMETER;
	static final String PRIVATE_KEY_PARAMETER = AKPJWK.PRIVATE_KEY_PARAMETER;
	private static final byte[] KEY_PAIR_VALIDATION_INPUT =
		"nimbus-mldsa-key-pair-check".getBytes(StandardCharsets.UTF_8);


	private volatile PrivateKey privateKey;
	private volatile byte[] privateData;
	private volatile PublicKey publicKey;
	private volatile byte[] publicData;
	private final JWSAlgorithm jwsAlgorithm;


	/**
	 * Builder for constructing ML-DSA JWKs.
	 */
	public static class Builder {


		private PrivateKey privateKey;
		private byte[] privateData;
		private PublicKey publicKey;
		private byte[] publicData;
		private KeyUse keyUse;
		private Set<KeyOperation> keyOps;
		private JWSAlgorithm jwsAlgorithm;
		private String keyID;
		private URI x509CertURL;
		private Base64URL x509CertThumbprint;
		private Base64URL x509CertSHA256Thumbprint;
		private List<Base64> x509CertChain;
		private Date expirationTime;
		private Date notBeforeTime;
		private Date issueTime;
		private KeyRevocation keyRevocation;
		private KeyStore keyStore;


		/**
		 * Creates a new ML-DSA JWK builder from the specified key pair.
		 *
		 * @param keyPair The ML-DSA key pair. Must not be {@code null}.
		 */
		public Builder(final KeyPair keyPair) {

			this(keyPair.getPrivate(), keyPair.getPublic());
		}


		/**
		 * Creates a new ML-DSA JWK builder from the specified keys.
		 *
		 * @param privateKey The ML-DSA private key. Must not be
		 *                   {@code null}.
		 * @param publicKey  The ML-DSA public key. Must not be
		 *                   {@code null}.
		 */
		public Builder(final PrivateKey privateKey, final PublicKey publicKey) {

			this.privateKey = Objects.requireNonNull(privateKey);
			this.publicKey = Objects.requireNonNull(publicKey);
			this.jwsAlgorithm = inferAndValidateMlDsaJwsAlgorithm(privateKey, publicKey);
		}


		/**
		 * Creates a new ML-DSA JWK builder from the specified public key.
		 *
		 * @param publicKey The ML-DSA public key. Must not be {@code null}.
		 */
		public Builder(final PublicKey publicKey) {

			this.publicKey = Objects.requireNonNull(publicKey);
			this.jwsAlgorithm = inferMlDsaJwsAlgorithmOrThrow(publicKey);
		}


		/**
		 * Creates a new ML-DSA JWK builder by copying the specified key.
		 *
		 * @param mldsaJWK The ML-DSA JWK to copy. Must not be {@code null}.
		 */
		public Builder(final MLDSAKey mldsaJWK) {

			privateKey = mldsaJWK.privateKey;
			privateData = mldsaJWK.privateData;
			publicKey = mldsaJWK.publicKey;
			publicData = mldsaJWK.publicData;
			keyUse = mldsaJWK.getKeyUse();
			keyOps = mldsaJWK.getKeyOperations();
			jwsAlgorithm = mldsaJWK.jwsAlgorithm;
			keyID = mldsaJWK.getKeyID();
			x509CertURL = mldsaJWK.getX509CertURL();
			x509CertThumbprint = mldsaJWK.getX509CertThumbprint();
			x509CertSHA256Thumbprint = mldsaJWK.getX509CertSHA256Thumbprint();
			x509CertChain = mldsaJWK.getX509CertChain();
			expirationTime = mldsaJWK.getExpirationTime();
			notBeforeTime = mldsaJWK.getNotBeforeTime();
			issueTime = mldsaJWK.getIssueTime();
			keyRevocation = mldsaJWK.getKeyRevocation();
			keyStore = mldsaJWK.getKeyStore();
		}


		public Builder privateKey(final PrivateKey privateKey) {

			this.privateKey = privateKey;
			return this;
		}


		public Builder keyUse(final KeyUse keyUse) {

			this.keyUse = keyUse;
			return this;
		}


		public Builder keyOperations(final Set<KeyOperation> keyOps) {

			this.keyOps = keyOps;
			return this;
		}


		public Builder algorithm(final Algorithm algorithm) {

			if (algorithm == null) {
				jwsAlgorithm = null;
				return this;
			}

			if (! (algorithm instanceof JWSAlgorithm) || ! JWSAlgorithm.Family.ML.contains((JWSAlgorithm)algorithm)) {
				throw new IllegalArgumentException("The algorithm must be an ML-DSA JWS algorithm");
			}

			jwsAlgorithm = (JWSAlgorithm)algorithm;
			return this;
		}


		public Builder keyID(final String keyID) {

			this.keyID = keyID;
			return this;
		}


		public Builder x509CertURL(final URI x509CertURL) {

			this.x509CertURL = x509CertURL;
			return this;
		}


		public Builder x509CertThumbprint(final Base64URL x509CertThumbprint) {

			this.x509CertThumbprint = x509CertThumbprint;
			return this;
		}


		public Builder x509CertSHA256Thumbprint(final Base64URL x509CertSHA256Thumbprint) {

			this.x509CertSHA256Thumbprint = x509CertSHA256Thumbprint;
			return this;
		}


		public Builder x509CertChain(final List<Base64> x509CertChain) {

			this.x509CertChain = x509CertChain;
			return this;
		}


		public Builder expirationTime(final Date expirationTime) {

			this.expirationTime = expirationTime;
			return this;
		}


		public Builder notBeforeTime(final Date notBeforeTime) {

			this.notBeforeTime = notBeforeTime;
			return this;
		}


		public Builder issueTime(final Date issueTime) {

			this.issueTime = issueTime;
			return this;
		}


		public Builder keyRevocation(final KeyRevocation keyRevocation) {

			this.keyRevocation = keyRevocation;
			return this;
		}


		public Builder keyStore(final KeyStore keyStore) {

			this.keyStore = keyStore;
			return this;
		}


		public MLDSAKey build() {

			JWSAlgorithm resolvedAlgorithm = jwsAlgorithm;

			if (resolvedAlgorithm == null) {
				if (privateKey != null && publicKey != null) {
					resolvedAlgorithm = inferAndValidateMlDsaJwsAlgorithm(privateKey, publicKey);
				} else if (publicKey != null) {
					resolvedAlgorithm = inferMlDsaJwsAlgorithmOrThrow(publicKey);
				} else if (privateKey != null) {
					resolvedAlgorithm = inferMlDsaJwsAlgorithmOrThrow(privateKey);
				} else {
					throw new IllegalStateException("ML-DSA JWS algorithm must not be null");
				}
			}

			return new MLDSAKey(
				privateKey,
				privateData,
				publicKey,
				publicData,
				keyUse,
				keyOps,
				resolvedAlgorithm,
				keyID,
				x509CertURL,
				x509CertThumbprint,
				x509CertSHA256Thumbprint,
				x509CertChain,
				expirationTime,
				notBeforeTime,
				issueTime,
				keyRevocation,
				keyStore
			);
		}
	}


	/**
	 * Creates a new ML-DSA JWK from the specified key pair.
	 *
	 * @param keyPair The ML-DSA key pair. Must not be {@code null}.
	 */
	public MLDSAKey(final KeyPair keyPair) {

		this(keyPair.getPrivate(), keyPair.getPublic());
	}


	/**
	 * Creates a new private ML-DSA JWK from the specified keys.
	 *
	 * @param privateKey The ML-DSA private key. Must not be {@code null}.
	 * @param publicKey  The ML-DSA public key. Must not be {@code null}.
	 */
	public MLDSAKey(final PrivateKey privateKey, final PublicKey publicKey) {

		this(
			Objects.requireNonNull(privateKey),
			null,
			Objects.requireNonNull(publicKey),
			null,
			KeyUse.SIGNATURE,
			KEY_OPS_SIGN,
			inferAndValidateMlDsaJwsAlgorithm(privateKey, publicKey),
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null
		);
	}


	/**
	 * Creates a new public ML-DSA JWK from the specified key.
	 *
	 * @param publicKey The ML-DSA public key. Must not be {@code null}.
	 */
	public MLDSAKey(final PublicKey publicKey) {

		this(
			null,
			null,
			Objects.requireNonNull(publicKey),
			null,
			KeyUse.SIGNATURE,
			KEY_OPS_VERIFY,
			inferMlDsaJwsAlgorithmOrThrow(publicKey),
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null,
			null
		);
	}


	private MLDSAKey(final PrivateKey privateKey,
			 final byte[] privateData,
			 final PublicKey publicKey,
			 final byte[] publicData,
			 final KeyUse keyUse,
			 final Set<KeyOperation> keyOps,
			 final JWSAlgorithm jwsAlgorithm,
			 final String keyId,
			 final URI x509CertURL,
			 final Base64URL x509CertThumbprint,
			 final Base64URL x509CertSHA256Thumbprint,
			 final List<Base64> x509CertChain,
			 final Date expirationTime,
			 final Date notBeforeTime,
			 final Date issueTime,
		final KeyRevocation keyRevocation,
		final KeyStore keyStore) {

		super(
			keyUse,
			keyOps,
			Objects.requireNonNull(jwsAlgorithm, "mlDsaJwsAlgorithm"),
			keyId,
			x509CertURL,
			x509CertThumbprint,
			x509CertSHA256Thumbprint,
			x509CertChain,
			expirationTime,
			notBeforeTime,
			issueTime,
			keyRevocation,
			keyStore
		);

		this.privateKey = privateKey;
		this.privateData = privateData != null ? Arrays.copyOf(privateData, privateData.length) : null;

		if (publicData == null && publicKey == null) {
			throw new IllegalArgumentException("ML-DSA keys require a public key representation");
		}

		this.publicKey = publicKey;
		this.publicData = publicData != null ? Arrays.copyOf(publicData, publicData.length) : null;
		this.jwsAlgorithm = jwsAlgorithm;

		if (getParsedX509CertChain() != null) {
			ensureMatches(getParsedX509CertChain());
		}
	}


	@Override
	public boolean isPrivate() {

		return privateKey != null || privateData != null;
	}


	@Override
	public PublicKey toPublicKey()
		throws JOSEException {

		return toMLDSAPublicKey();
	}


	@Override
	public PrivateKey toPrivateKey()
		throws JOSEException {

		if (! isPrivate()) {
			return null;
		}

		if (privateData == null && privateKey != null && privateKey.getEncoded() == null) {
			return privateKey;
		}

		return toMLDSAPrivateKey();
	}


	@Override
	public KeyPair toKeyPair()
		throws JOSEException {

		return toKeyPair(null);
	}


	public KeyPair toKeyPair(final Provider provider)
		throws JOSEException {

		final PrivateKey resolvedPrivateKey;

		if (! isPrivate()) {
			resolvedPrivateKey = null;
		} else if (privateData == null && privateKey != null && privateKey.getEncoded() == null) {
			resolvedPrivateKey = privateKey;
		} else {
			resolvedPrivateKey = toMLDSAPrivateKey(provider);
		}

		return new KeyPair(toMLDSAPublicKey(provider), resolvedPrivateKey);
	}


	@Override
	public boolean matches(final X509Certificate cert) {

		try {
			return Arrays.equals(publicDataBytes(), extractPublicData(cert.getPublicKey()));
		} catch (IllegalStateException e) {
			return false;
		}
	}


	private void ensureMatches(final List<X509Certificate> chain) {

		if (chain == null) {
			return;
		}

		if (! matches(chain.get(0))) {
			throw new IllegalArgumentException("The public subject key info of the first X.509 certificate in the chain must match the JWK type and public parameters");
		}
	}


	@SuppressWarnings("deprecation")
	@Override
	public MLDSAKey toPublicJWK() {

		return new MLDSAKey(
			null,
			null,
			publicKey,
			publicData,
			getKeyUse(),
			getKeyOperations(),
			jwsAlgorithm,
			getKeyID(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertSHA256Thumbprint(),
			getX509CertChain(),
			getExpirationTime(),
			getNotBeforeTime(),
			getIssueTime(),
			getKeyRevocation(),
			getKeyStore()
		);
	}


	@SuppressWarnings("deprecation")
	@Override
	public MLDSAKey toRevokedJWK(final KeyRevocation keyRevocation) {

		if (getKeyRevocation() != null) {
			throw new IllegalStateException("Already revoked");
		}

		return new MLDSAKey(
			privateKey,
			privateData,
			publicKey,
			publicData,
			getKeyUse(),
			getKeyOperations(),
			jwsAlgorithm,
			getKeyID(),
			getX509CertURL(),
			getX509CertThumbprint(),
			getX509CertSHA256Thumbprint(),
			getX509CertChain(),
			getExpirationTime(),
			getNotBeforeTime(),
			getIssueTime(),
			Objects.requireNonNull(keyRevocation, "keyRevocation"),
			getKeyStore()
		);
	}


	@Override
	public int size() {

		return ByteUtils.bitLength(publicDataBytes());
	}

	/**
	 * Returns the ML-DSA private key.
	 *
	 * <p>Uses the BouncyCastle JCA provider.
	 *
	 * @return The ML-DSA private key.
	 *
	 * @throws JOSEException If the key cannot be obtained.
	 */
	public MLDSAPrivateKey toMLDSAPrivateKey()
		throws JOSEException {

		return toMLDSAPrivateKey(null);
	}


	/**
	 * Returns the ML-DSA private key.
	 *
	 * @param provider The JCA provider to use, {@code null} to use
	 *                 BouncyCastle.
	 *
	 * @return The ML-DSA private key.
	 *
	 * @throws JOSEException If the key cannot be obtained.
	 */
	public MLDSAPrivateKey toMLDSAPrivateKey(final Provider provider)
		throws JOSEException {

		PrivateKey mldsaPrivateKey = privateKey;
		if (provider == null && mldsaPrivateKey instanceof MLDSAPrivateKey) {
			return (MLDSAPrivateKey)mldsaPrivateKey;
		}

		Provider jcaProvider = resolveJCAProvider(provider);

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", jcaProvider);

			if (mldsaPrivateKey != null) {
				byte[] encoded = mldsaPrivateKey.getEncoded();

				if (encoded != null && encoded.length > 0) {
					// Generic JCA keys can still carry a valid ML-DSA PKCS#8 encoding
					// even if they do not expose the BC-specific MLDSAPrivateKey
					// interface. Prefer that canonical encoding when rehydrating such
					// wrapped / provider-agnostic keys.
					mldsaPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
				}
			}

			if (mldsaPrivateKey == null) {
				byte[] privateKeyData = Objects.requireNonNull(
					privateDataBytes(),
					"ML-DSA private key material is required for signing"
				);

				mldsaPrivateKey = keyFactory.generatePrivate(
					new MLDSAPrivateKeySpec(mldsaParameterSpec(), privateKeyData, publicDataBytes())
				);
			}

			if (mldsaPrivateKey instanceof MLDSAPrivateKey) {
				if (provider == null) {
					privateKey = mldsaPrivateKey;
				}

				return (MLDSAPrivateKey)mldsaPrivateKey;
			}

			throw new JOSEException(
				"Provider returned unsupported ML-DSA private key implementation: " +
					mldsaPrivateKey.getClass().getName()
			);

		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new JOSEException(e);
		}
	}


	/**
	 * Returns the ML-DSA public key.
	 *
	 * <p>Uses the BouncyCastle JCA provider.
	 *
	 * @return The ML-DSA public key.
	 *
	 * @throws JOSEException If the key cannot be obtained.
	 */
	public MLDSAPublicKey toMLDSAPublicKey()
		throws JOSEException {

		return toMLDSAPublicKey(null);
	}


	/**
	 * Returns the ML-DSA public key.
	 *
	 * @param provider The JCA provider to use, {@code null} to use
	 *                 BouncyCastle.
	 *
	 * @return The ML-DSA public key.
	 *
	 * @throws JOSEException If the key cannot be obtained.
	 */
	public MLDSAPublicKey toMLDSAPublicKey(final Provider provider)
		throws JOSEException {

		PublicKey mldsaPublicKey = publicKey;
		if (provider == null && mldsaPublicKey instanceof MLDSAPublicKey) {
			return (MLDSAPublicKey)mldsaPublicKey;
		}

		Provider jcaProvider = resolveJCAProvider(provider);

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", jcaProvider);

			if (mldsaPublicKey != null) {
				byte[] encoded = mldsaPublicKey.getEncoded();

				if (encoded != null && encoded.length > 0) {
					// Same rationale as the private-key branch above: generic /
					// wrapped JCA keys should still round-trip via their canonical
					// X.509 SubjectPublicKeyInfo encoding.
					mldsaPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
				}
			}

			if (mldsaPublicKey == null) {
				mldsaPublicKey = keyFactory.generatePublic(
					new MLDSAPublicKeySpec(mldsaParameterSpec(), publicDataBytes())
				);
			}

			if (mldsaPublicKey instanceof MLDSAPublicKey) {
				if (provider == null) {
					publicKey = mldsaPublicKey;
				}

				return (MLDSAPublicKey)mldsaPublicKey;
			}

			throw new JOSEException(
				"Provider returned unsupported ML-DSA public key implementation: " +
					mldsaPublicKey.getClass().getName()
			);

		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new JOSEException(e);
		}
	}


	/**
	 * Returns the ML-DSA parameter specification.
	 *
	 * @return The ML-DSA parameter specification.
	 *
	 * @throws JOSEException If the algorithm is unsupported.
	 */
	public MLDSAParameterSpec mldsaParameterSpec()
		throws JOSEException {

		String name = jwsAlgorithm.getName();

		if (JWSAlgorithm.ML_DSA_44.getName().equals(name)) {
			return MLDSAParameterSpec.ml_dsa_44;
		}

		if (JWSAlgorithm.ML_DSA_65.getName().equals(name)) {
			return MLDSAParameterSpec.ml_dsa_65;
		}

		if (JWSAlgorithm.ML_DSA_87.getName().equals(name)) {
			return MLDSAParameterSpec.ml_dsa_87;
		}

		throw new JOSEException("Unsupported JWS algorithm: " + jwsAlgorithm.getName());
	}


	/**
	 * Parses an ML-DSA JWK from the specified string.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The ML-DSA JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to an ML-DSA
	 *                        JWK.
	 */
	public static MLDSAKey parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}


	/**
	 * Parses an ML-DSA JWK from the specified JSON object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The ML-DSA JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        ML-DSA JWK.
	 */
	public static MLDSAKey parse(final Map<String, Object> jsonObject)
		throws ParseException {

		String keyType = JSONObjectUtils.getString(jsonObject, "kty");

		if (! KEY_TYPE.getValue().equals(keyType) && ! LEGACY_KEY_TYPE.getValue().equals(keyType)) {
			throw new ParseException(
				String.format(
					"The key type kty must be %s or legacy %s",
					KEY_TYPE.getValue(),
					LEGACY_KEY_TYPE.getValue()
				),
				0
			);
		}

		JWSAlgorithm algorithm = parseAlgorithmOrThrow(jsonObject);
		Base64URL publicData = JSONObjectUtils.getBase64URL(jsonObject, PUBLIC_KEY_PARAMETER);

		if (publicData == null) {
			throw new ParseException("Missing public key \"" + PUBLIC_KEY_PARAMETER + "\" parameter", 0);
		}

		Base64URL privateData = JSONObjectUtils.getBase64URL(jsonObject, PRIVATE_KEY_PARAMETER);

		return new MLDSAKey(
			null,
			privateData == null ? null : privateData.decode(),
			null,
			publicData.decode(),
			JWKMetadata.parseKeyUse(jsonObject),
			JWKMetadata.parseKeyOperations(jsonObject),
			algorithm,
			JSONObjectUtils.getString(jsonObject, "kid"),
			JSONObjectUtils.getURI(jsonObject, "x5u"),
			JSONObjectUtils.getBase64URL(jsonObject, "x5t"),
			JSONObjectUtils.getBase64URL(jsonObject, "x5t#S256"),
			JWKMetadata.parseX509CertChain(jsonObject),
			JSONObjectUtils.getEpochSecondAsDate(jsonObject, "exp"),
			JSONObjectUtils.getEpochSecondAsDate(jsonObject, "nbf"),
			JSONObjectUtils.getEpochSecondAsDate(jsonObject, "iat"),
			JWKMetadata.parseKeyRevocation(jsonObject),
			null
		);
	}


	/**
	 * Parses a public ML-DSA JWK from the specified X.509 certificate.
	 *
	 * <p><strong>Important:</strong> The X.509 certificate is not
	 * validated!
	 *
	 * @param cert The X.509 certificate. Must not be {@code null}.
	 *
	 * @return The public ML-DSA JWK.
	 *
	 * @throws JOSEException If parsing failed.
	 */
	public static MLDSAKey parse(final X509Certificate cert)
		throws JOSEException {

		if (! isMLDSAPublicKey(cert.getPublicKey())) {
			throw new JOSEException("The public key of the X.509 certificate is not ML-DSA");
		}

		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

			return new Builder(cert.getPublicKey())
				.keyUse(KeyUse.from(cert))
				.keyID(cert.getSerialNumber().toString(10))
				.x509CertChain(Collections.singletonList(Base64.encode(cert.getEncoded())))
				.x509CertSHA256Thumbprint(Base64URL.encode(sha256.digest(cert.getEncoded())))
				.expirationTime(cert.getNotAfter())
				.notBeforeTime(cert.getNotBefore())
				.build();

		} catch (NoSuchAlgorithmException e) {
			throw new JOSEException("Couldn't encode x5t parameter: " + e.getMessage(), e);
		} catch (CertificateEncodingException e) {
			throw new JOSEException("Couldn't encode x5c parameter: " + e.getMessage(), e);
		}
	}


	/**
	 * Loads a public / private ML-DSA JWK from the specified JCA key
	 * store. Requires BouncyCastle.
	 *
	 * <p><strong>Important:</strong> The X.509 certificate is not
	 * validated!
	 *
	 * @param keyStore The key store. Must not be {@code null}.
	 * @param alias    The alias. Must not be {@code null}.
	 * @param pin      The pin to unlock the private key if any, empty or
	 *                 {@code null} if not required.
	 *
	 * @return The public / private ML-DSA JWK, {@code null} if no key with
	 *         the specified alias was found.
	 *
	 * @throws KeyStoreException On a key store exception.
	 * @throws JOSEException     If ML-DSA key loading failed.
	 */
	public static MLDSAKey load(final KeyStore keyStore,
				    final String alias,
				    final char[] pin)
		throws KeyStoreException, JOSEException {

		Certificate cert = keyStore.getCertificate(alias);

		if (! (cert instanceof X509Certificate)) {
			return null;
		}

		X509Certificate x509Cert = (X509Certificate)cert;

		if (! isMLDSAPublicKey(x509Cert.getPublicKey())) {
			throw new JOSEException("Couldn't load ML-DSA JWK: The key algorithm is not ML-DSA");
		}

		MLDSAKey mldsaJWK = MLDSAKey.parse(x509Cert);

		// Let kid=alias
		mldsaJWK = new Builder(mldsaJWK)
			.keyID(alias)
			.keyStore(keyStore)
			.build();

		Key key;
		try {
			key = keyStore.getKey(alias, pin);
		} catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
			throw new JOSEException("Couldn't retrieve private ML-DSA key (bad pin?): " + e.getMessage(), e);
		}

		if (key instanceof PrivateKey && inferMlDsaJwsAlgorithm((PrivateKey)key, x509Cert.getPublicKey()) != null) {
			ensurePrivateKeyMatchesPublicKey((PrivateKey)key, x509Cert.getPublicKey(), keyStore.getProvider());

			return new Builder(mldsaJWK)
				.privateKey((PrivateKey)key)
				.build();
		}

		return mldsaJWK;
	}


	static boolean isMLDSAPublicKey(final PublicKey publicKey) {

		return inferMlDsaJwsAlgorithm(null, publicKey) != null;
	}


	JWSAlgorithm mlDsaJwsAlgorithm() {

		return jwsAlgorithm;
	}


	@Override
	public boolean equals(final Object o) {

		if (this == o) {
			return true;
		}

		if (! (o instanceof MLDSAKey)) {
			return false;
		}

		MLDSAKey that = (MLDSAKey)o;
		return super.equals(o) &&
			Arrays.equals(publicDataBytes(), that.publicDataBytes()) &&
			Arrays.equals(privateDataBytes(), that.privateDataBytes());
	}


	@Override
	public int hashCode() {

		int h = super.hashCode();
		h = 31 * h + Arrays.hashCode(publicDataBytes());
		h = 31 * h + Arrays.hashCode(privateDataBytes());
		return h;
	}


	private static JWSAlgorithm inferMlDsaJwsAlgorithm(final PrivateKey privateKey, final PublicKey publicKey) {

		JWSAlgorithm fromName = algorithmFromName(
			privateKey != null ? privateKey.getAlgorithm() : publicKey.getAlgorithm()
		);

		if (fromName != null) {
			return fromName;
		}

		// Slow path, never exercised in the current implementation.
		byte[] encoded = privateKey != null ? privateKey.getEncoded() : publicKey.getEncoded();

		if (encoded == null || encoded.length == 0) {
			return null;
		}

		try {
			ASN1ObjectIdentifier oid =
				privateKey != null ?
					PrivateKeyInfo.getInstance(encoded).getPrivateKeyAlgorithm().getAlgorithm() :
					SubjectPublicKeyInfo.getInstance(encoded).getAlgorithm().getAlgorithm();

			return algorithmFromOid(oid);

		} catch (Exception e) {
			return null;
		}
	}


	private static JWSAlgorithm inferMlDsaJwsAlgorithmOrThrow(final PrivateKey privateKey) {

		JWSAlgorithm algorithm = inferMlDsaJwsAlgorithm(
			Objects.requireNonNull(privateKey, "privateKey"),
			null
		);

		if (algorithm == null) {
			throw new IllegalArgumentException("Invalid ML-DSA private key");
		}

		return algorithm;
	}


	private static JWSAlgorithm inferMlDsaJwsAlgorithmOrThrow(final PublicKey publicKey) {

		JWSAlgorithm algorithm = inferMlDsaJwsAlgorithm(
			null,
			Objects.requireNonNull(publicKey, "publicKey")
		);

		if (algorithm == null) {
			throw new IllegalArgumentException("Invalid ML-DSA public key");
		}

		return algorithm;
	}


	private static JWSAlgorithm inferAndValidateMlDsaJwsAlgorithm(final PrivateKey privateKey,
								  final PublicKey publicKey) {

		JWSAlgorithm privateAlgorithm = inferMlDsaJwsAlgorithmOrThrow(privateKey);
		JWSAlgorithm publicAlgorithm = inferMlDsaJwsAlgorithmOrThrow(publicKey);

		if (! privateAlgorithm.equals(publicAlgorithm)) {
			throw new IllegalArgumentException(
				String.format(
					"ML-DSA key pair algorithm mismatch: private=%s public=%s",
					privateAlgorithm.getName(),
					publicAlgorithm.getName()
				)
			);
		}

		return privateAlgorithm;
	}


	private static void ensurePrivateKeyMatchesPublicKey(final PrivateKey privateKey,
								 final PublicKey publicKey,
								 final Provider provider)
		throws JOSEException {

		MLDSAKey key = new MLDSAKey(privateKey, publicKey);
		JWSAlgorithm algorithm = key.mlDsaJwsAlgorithm();

		try {
			Signature signer = MLDSA.getSignerAndVerifier(algorithm, provider);
			signer.initSign(key.toKeyPair(provider).getPrivate());
			signer.update(KEY_PAIR_VALIDATION_INPUT);
			byte[] signature = signer.sign();

			Signature verifier = MLDSA.getSignerAndVerifier(algorithm, null);
			verifier.initVerify(key.toMLDSAPublicKey());
			verifier.update(KEY_PAIR_VALIDATION_INPUT);

			if (! verifier.verify(signature)) {
				throw new JOSEException("Couldn't load ML-DSA JWK: The private key doesn't match the public X.509 certificate");
			}

		} catch (GeneralSecurityException e) {
			throw new JOSEException("Couldn't load ML-DSA JWK: " + e.getMessage(), e);
		}
	}


	@Override
	protected Base64URL encodedPublicData() {

		return Base64URL.encode(publicDataBytes());
	}


	private byte[] publicDataBytes() {

		byte[] data = publicData;

		if (data == null) {
			data = extractPublicData(publicKey);
			publicData = data;
		}

		return data;
	}


	@Override
	protected Base64URL encodedPrivateData() {

		byte[] data = privateDataBytes();

		if (data != null) {
			return Base64URL.encode(data);
		}

		return null;
	}


	private byte[] privateDataBytes() {

		byte[] data = privateData;

		if (data == null && privateKey != null) {
			data = extractPrivateData(privateKey);
			privateData = data;
		}

		return data;
	}


	private static byte[] extractPublicData(final PublicKey publicKey) {

		if (publicKey instanceof MLDSAPublicKey) {
			return ((MLDSAPublicKey)publicKey).getPublicData();
		}

		try {
			return SubjectPublicKeyInfo.getInstance(
				Objects.requireNonNull(publicKey.getEncoded(), "publicKey.encoded")
			).getPublicKeyData().getOctets();

		} catch (Exception e) {
			throw new IllegalStateException("Unable to extract ML-DSA public key bytes", e);
		}
	}


	private static byte[] extractPrivateData(final PrivateKey privateKey) {

		if (privateKey instanceof MLDSAPrivateKey) {
			return ((MLDSAPrivateKey)privateKey).getPrivateData();
		}

		try {
			return PrivateKeyInfo.getInstance(
				Objects.requireNonNull(privateKey.getEncoded(), "privateKey.encoded")
			).getPrivateKey().getOctets();

		} catch (Exception e) {
			throw new IllegalStateException("Unable to extract ML-DSA private key bytes", e);
		}
	}


	private static JWSAlgorithm parseAlgorithmOrThrow(final Map<String, Object> jsonObject)
		throws ParseException {

		String algorithmName = JSONObjectUtils.getString(jsonObject, "alg");
		JWSAlgorithm algorithm = algorithmFromName(algorithmName);

		if (algorithm == null) {
			throw new ParseException("Unsupported ML-DSA JWS algorithm: " + algorithmName, 0);
		}

		return algorithm;
	}

	private static JWSAlgorithm algorithmFromName(final String algorithm) {

		if (algorithm == null) {
			return null;
		}

		if (JWSAlgorithm.ML_DSA_44.getName().equals(algorithm)) {
			return JWSAlgorithm.ML_DSA_44;
		}

		if (JWSAlgorithm.ML_DSA_65.getName().equals(algorithm)) {
			return JWSAlgorithm.ML_DSA_65;
		}

		if (JWSAlgorithm.ML_DSA_87.getName().equals(algorithm)) {
			return JWSAlgorithm.ML_DSA_87;
		}

		return null;
	}


	private static JWSAlgorithm algorithmFromOid(final ASN1ObjectIdentifier oid) {

		if (oid == null) {
			return null;
		}

		if (oid.equals(NISTObjectIdentifiers.id_ml_dsa_44)) {
			return JWSAlgorithm.ML_DSA_44;
		}

		if (oid.equals(NISTObjectIdentifiers.id_ml_dsa_65)) {
			return JWSAlgorithm.ML_DSA_65;
		}

		if (oid.equals(NISTObjectIdentifiers.id_ml_dsa_87)) {
			return JWSAlgorithm.ML_DSA_87;
		}

		if (oid.equals(BCObjectIdentifiers.dilithium2)) {
			return JWSAlgorithm.ML_DSA_44;
		}

		if (oid.equals(BCObjectIdentifiers.dilithium3)) {
			return JWSAlgorithm.ML_DSA_65;
		}

		if (oid.equals(BCObjectIdentifiers.dilithium5)) {
			return JWSAlgorithm.ML_DSA_87;
		}

		return null;
	}


	private static Provider resolveJCAProvider(final Provider provider) {

		return provider != null ? provider : BouncyCastleProviderSingleton.getInstance();
	}
}
