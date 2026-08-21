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
import com.nimbusds.jose.Requirement;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

import java.net.URI;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;


/**
 * PQEID: X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768,
 * {@code draft-connolly-cfrg-xwing-kem}) {@link JWK} implementation.
 *
 * <p>This is <strong>not</strong> a standard/registered JOSE key type - there is no
 * IETF-registered JOSE {@code kty}/{@code alg} for X-Wing yet (as of this writing the
 * relevant drafts, e.g. {@code draft-reddy-cose-jose-pqc-kem}, are still in discussion).
 * {@code "XWING"} is a project-specific {@code kty} chosen for a research POC, not meant
 * to interoperate with anything outside this project.
 *
 * <p>Stores raw key bytes directly ({@code x} = public key encoding, {@code d} = private
 * key seed), the same pattern {@link OctetKeyPair} uses for Ed25519/X25519 - rather than
 * routing through a JCA {@code KeyFactory}/{@code Provider} the way {@link MLDSAKey} does,
 * because BouncyCastle has no JCA-level wrapper for X-Wing (only the "lightweight"
 * {@code org.bouncycastle.pqc.crypto.xwing} API used here directly).
 *
 * <p>Example JSON object representation of a public XWING JWK:
 *
 * <pre>
 * {
 *   "kty" : "XWING",
 *   "x"   : "..."
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a private XWING JWK:
 *
 * <pre>
 * {
 *   "kty" : "XWING",
 *   "x"   : "...",
 *   "d"   : "..."
 * }
 * </pre>
 */
public class XWingKey extends JWK implements AsymmetricJWK {


	private static final long serialVersionUID = 1L;


	/**
	 * PQEID: custom, unregistered key type for this POC.
	 */
	public static final KeyType KEY_TYPE = new KeyType("XWING", Requirement.OPTIONAL);


	private static final String PUBLIC_KEY_PARAMETER = "x";
	private static final String PRIVATE_KEY_PARAMETER = "d";


	private final Base64URL x;
	private final byte[] decodedX;
	private final Base64URL d;
	private final byte[] decodedD;


	/**
	 * Creates a new X-Wing JWK with only the public part.
	 *
	 * @param x The public key encoding. Must not be {@code null}.
	 */
	public XWingKey(final Base64URL x) {

		this(x, null);
	}


	/**
	 * Creates a new X-Wing JWK.
	 *
	 * @param x The public key encoding. Must not be {@code null}.
	 * @param d The private key seed, {@code null} if not specified (for a
	 *          public key).
	 */
	public XWingKey(final Base64URL x, final Base64URL d) {

		this(x, d, null, null, null, null, null, null, null, null, null, null, null, null, null);
	}


	/**
	 * Creates a new X-Wing JWK with the specified parameters.
	 *
	 * @param x          The public key encoding. Must not be {@code null}.
	 * @param d          The private key seed, {@code null} if not specified
	 *                   (for a public key).
	 * @param use        The key use, {@code null} if not specified.
	 * @param ops        The key operations, {@code null} if not specified.
	 * @param alg        The intended JOSE algorithm for the key, {@code null}
	 *                   if not specified.
	 * @param kid        The key ID, {@code null} if not specified.
	 * @param x5u        The X.509 certificate URL, {@code null} if not
	 *                   specified.
	 * @param x5t        The X.509 certificate SHA-1 thumbprint, {@code null}
	 *                   if not specified.
	 * @param x5t256     The X.509 certificate SHA-256 thumbprint,
	 *                   {@code null} if not specified.
	 * @param x5c        The X.509 certificate chain, {@code null} if not
	 *                   specified.
	 * @param exp        The key expiration time, {@code null} if not
	 *                   specified.
	 * @param nbf        The key not-before time, {@code null} if not
	 *                   specified.
	 * @param iat        The key issued-at time, {@code null} if not
	 *                   specified.
	 * @param revocation The key revocation, {@code null} if not specified.
	 * @param ks         Reference to the underlying key store, {@code null}
	 *                   if not specified.
	 */
	public XWingKey(final Base64URL x, final Base64URL d,
			final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
			final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
			final Date exp, final Date nbf, final Date iat,
			final KeyRevocation revocation, final KeyStore ks) {

		super(KEY_TYPE, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);

		this.x = Objects.requireNonNull(x, "The \"" + PUBLIC_KEY_PARAMETER + "\" (public key) parameter must not be null");
		this.decodedX = x.decode();

		this.d = d;
		this.decodedD = d == null ? null : d.decode();
	}


	/**
	 * PQEID: generates a fresh X-Wing key pair using BouncyCastle's
	 * lightweight API and the default {@link SecureRandom}.
	 *
	 * @return A new private X-Wing JWK (contains both public and private
	 *         parts).
	 */
	public static XWingKey generate() {

		return generate(new SecureRandom());
	}


	/**
	 * PQEID: generates a fresh X-Wing key pair using BouncyCastle's
	 * lightweight API.
	 *
	 * @param random The secure random generator to use. Must not be
	 *               {@code null}.
	 *
	 * @return A new private X-Wing JWK (contains both public and private
	 *         parts).
	 */
	public static XWingKey generate(final SecureRandom random) {

		XWingKeyPairGenerator generator = new XWingKeyPairGenerator();
		generator.init(new XWingKeyGenerationParameters(random));
		AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

		XWingPublicKeyParameters pub = (XWingPublicKeyParameters) keyPair.getPublic();
		XWingPrivateKeyParameters priv = (XWingPrivateKeyParameters) keyPair.getPrivate();

		return new XWingKey(
			Base64URL.encode(pub.getEncoded()),
			Base64URL.encode(priv.getSeed())
		);
	}


	/**
	 * Gets the public key encoding ({@code x} parameter).
	 *
	 * @return The public key encoding.
	 */
	public Base64URL getX() {

		return x;
	}


	/**
	 * Gets the public key encoding, decoded from Base64URL.
	 *
	 * @return The public key bytes.
	 */
	public byte[] getDecodedX() {

		return decodedX.clone();
	}


	/**
	 * Gets the private key seed ({@code d} parameter).
	 *
	 * @return The private key seed, {@code null} if not specified (for a
	 *         public key).
	 */
	public Base64URL getD() {

		return d;
	}


	/**
	 * Gets the private key seed, decoded from Base64URL.
	 *
	 * @return The private key seed bytes, {@code null} if not specified
	 *         (for a public key).
	 */
	public byte[] getDecodedD() {

		return decodedD == null ? null : decodedD.clone();
	}


	/**
	 * PQEID: converts to the BouncyCastle lightweight public key
	 * parameters, for use by
	 * {@link com.nimbusds.jose.crypto.XWingEncrypter}/{@code XWingDecrypter}.
	 *
	 * @return The BouncyCastle public key parameters.
	 */
	public XWingPublicKeyParameters toBCPublicKeyParameters() {

		return new XWingPublicKeyParameters(decodedX);
	}


	/**
	 * PQEID: converts to the BouncyCastle lightweight private key
	 * parameters (rebuilt from the stored seed).
	 *
	 * @return The BouncyCastle private key parameters.
	 *
	 * @throws JOSEException If this JWK has no private part.
	 */
	public XWingPrivateKeyParameters toBCPrivateKeyParameters()
		throws JOSEException {

		if (decodedD == null) {
			throw new JOSEException("This X-Wing JWK does not contain a private key (\"" + PRIVATE_KEY_PARAMETER + "\")");
		}

		return new XWingPrivateKeyParameters(decodedD);
	}


	@Override
	public boolean isPrivate() {

		return d != null;
	}


	/**
	 * Returns a copy of this X-Wing JWK with any private values removed.
	 *
	 * @return The copied public X-Wing JWK.
	 */
	@Override
	public XWingKey toPublicJWK() {

		return new XWingKey(
			x, null,
			getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
			getX509CertURL(), getX509CertThumbprint(), getX509CertSHA256Thumbprint(), getX509CertChain(),
			getExpirationTime(), getNotBeforeTime(), getIssueTime(), getKeyRevocation(),
			getKeyStore());
	}


	@Override
	public XWingKey toRevokedJWK(final KeyRevocation keyRevocation) {

		if (getKeyRevocation() != null) {
			throw new IllegalStateException("Already revoked");
		}

		return new XWingKey(
			x, d,
			getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
			getX509CertURL(), getX509CertThumbprint(), getX509CertSHA256Thumbprint(), getX509CertChain(),
			getExpirationTime(), getNotBeforeTime(), getIssueTime(),
			Objects.requireNonNull(keyRevocation, "keyRevocation"),
			getKeyStore());
	}


	/**
	 * PQEID: X-Wing has no JCA {@code KeyFactory}/{@code Provider} in
	 * BouncyCastle (only the lightweight {@code org.bouncycastle.pqc.crypto.xwing}
	 * API, see {@link #toBCPublicKeyParameters()}) - so there is no standard
	 * {@link java.security.PublicKey} representation to return here.
	 *
	 * @throws JOSEException Always - not supported.
	 */
	@Override
	public java.security.PublicKey toPublicKey()
		throws JOSEException {

		throw new JOSEException("X-Wing keys have no JCA PublicKey representation, use toBCPublicKeyParameters() instead");
	}


	/**
	 * PQEID: see {@link #toPublicKey()} - same reasoning applies to the
	 * private key.
	 *
	 * @throws JOSEException Always - not supported.
	 */
	@Override
	public java.security.PrivateKey toPrivateKey()
		throws JOSEException {

		throw new JOSEException("X-Wing keys have no JCA PrivateKey representation, use toBCPrivateKeyParameters() instead");
	}


	/**
	 * PQEID: see {@link #toPublicKey()} - same reasoning applies to the
	 * key pair.
	 *
	 * @throws JOSEException Always - not supported.
	 */
	@Override
	public java.security.KeyPair toKeyPair()
		throws JOSEException {

		throw new JOSEException("X-Wing keys have no JCA KeyPair representation, use toBCPublicKeyParameters()/toBCPrivateKeyParameters() instead");
	}


	@Override
	public boolean matches(final X509Certificate cert) {

		// X.509 does not (yet) support X-Wing
		return false;
	}


	@Override
	public LinkedHashMap<String, ?> getRequiredParams() {

		// Put mandatory params in sorted order
		LinkedHashMap<String, String> requiredParams = new LinkedHashMap<>();
		requiredParams.put("kty", getKeyType().getValue());
		requiredParams.put(PUBLIC_KEY_PARAMETER, x.toString());
		return requiredParams;
	}


	@Override
	public Map<String, Object> toJSONObject() {

		Map<String, Object> o = super.toJSONObject();

		o.put(PUBLIC_KEY_PARAMETER, x.toString());

		if (d != null) {
			o.put(PRIVATE_KEY_PARAMETER, d.toString());
		}

		return o;
	}


	@Override
	public int size() {

		return ByteUtils.bitLength(decodedX);
	}


	/**
	 * Parses an X-Wing JWK from the specified string.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The X-Wing JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to an X-Wing
	 *                        JWK.
	 */
	public static XWingKey parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}


	/**
	 * Parses an X-Wing JWK from the specified JSON object representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X-Wing JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        X-Wing JWK.
	 */
	public static XWingKey parse(final Map<String, Object> jsonObject)
		throws ParseException {

		String keyType = JSONObjectUtils.getString(jsonObject, "kty");

		if (! KEY_TYPE.getValue().equals(keyType)) {
			throw new ParseException("The key type kty must be " + KEY_TYPE.getValue(), 0);
		}

		Base64URL x = JSONObjectUtils.getBase64URL(jsonObject, PUBLIC_KEY_PARAMETER);

		if (x == null) {
			throw new ParseException("Missing public key \"" + PUBLIC_KEY_PARAMETER + "\" parameter", 0);
		}

		Base64URL d = JSONObjectUtils.getBase64URL(jsonObject, PRIVATE_KEY_PARAMETER);

		return new XWingKey(
			x, d,
			JWKMetadata.parseKeyUse(jsonObject),
			JWKMetadata.parseKeyOperations(jsonObject),
			JWKMetadata.parseAlgorithm(jsonObject),
			JWKMetadata.parseKeyID(jsonObject),
			JWKMetadata.parseX509CertURL(jsonObject),
			JWKMetadata.parseX509CertThumbprint(jsonObject),
			JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
			JWKMetadata.parseX509CertChain(jsonObject),
			JWKMetadata.parseExpirationTime(jsonObject),
			JWKMetadata.parseNotBeforeTime(jsonObject),
			JWKMetadata.parseIssueTime(jsonObject),
			JWKMetadata.parseKeyRevocation(jsonObject),
			null
		);
	}


	/**
	 * Builder for constructing X-Wing JWKs.
	 *
	 * <p>Example use:
	 *
	 * <pre>
	 * XWingKey key = new XWingKey.Builder(x, d)
	 *     .keyID("123")
	 *     .build();
	 * </pre>
	 */
	public static class Builder {


		private final Base64URL x;
		private Base64URL d;
		private KeyUse keyUse;
		private Set<KeyOperation> keyOps;
		private Algorithm algorithm;
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
		 * Creates a new X-Wing JWK builder.
		 *
		 * @param x The public key encoding. Must not be {@code null}.
		 */
		public Builder(final Base64URL x) {

			this.x = x;
		}


		/**
		 * Creates a new X-Wing JWK builder by copying the specified
		 * key.
		 *
		 * @param xwKey The X-Wing JWK to copy. Must not be
		 *              {@code null}.
		 */
		public Builder(final XWingKey xwKey) {

			x = xwKey.x;
			d = xwKey.d;
			keyUse = xwKey.getKeyUse();
			keyOps = xwKey.getKeyOperations();
			algorithm = xwKey.getAlgorithm();
			keyID = xwKey.getKeyID();
			x509CertURL = xwKey.getX509CertURL();
			x509CertThumbprint = xwKey.getX509CertThumbprint();
			x509CertSHA256Thumbprint = xwKey.getX509CertSHA256Thumbprint();
			x509CertChain = xwKey.getX509CertChain();
			expirationTime = xwKey.getExpirationTime();
			notBeforeTime = xwKey.getNotBeforeTime();
			issueTime = xwKey.getIssueTime();
			keyRevocation = xwKey.getKeyRevocation();
			keyStore = xwKey.getKeyStore();
		}


		public Builder d(final Base64URL d) {

			this.d = d;
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

			this.algorithm = algorithm;
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


		public XWingKey build() {

			return new XWingKey(
				x, d,
				keyUse, keyOps, algorithm, keyID,
				x509CertURL, x509CertThumbprint, x509CertSHA256Thumbprint, x509CertChain,
				expirationTime, notBeforeTime, issueTime,
				keyRevocation, keyStore);
		}
	}
}
