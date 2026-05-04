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
import com.nimbusds.jose.ByteArrayJWSInput;
import com.nimbusds.jose.CompletableJWSObjectSigning;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSInput;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSSignerOption;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.MLDSA;
import com.nimbusds.jose.crypto.impl.MLDSAProvider;
import com.nimbusds.jose.crypto.opts.UserAuthenticationRequired;
import com.nimbusds.jose.jwk.MLDSAKey;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;

import java.security.KeyFactory;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collections;
import java.util.Set;


/**
 * ML-DSA signer of {@link com.nimbusds.jose.JWSObject JWS objects}.
 * Accepts a private {@link MLDSAKey} or a private key from which the
 * corresponding public key can be derived.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_44}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_65}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ML_DSA_87}
 * </ul>
 *
 * @version 2026-05-04
 */
@ThreadSafe
public class MLDSASigner extends MLDSAProvider implements JWSSigner {


	private final MLDSAKey privateKey;


	private final Set<JWSSignerOption> opts;


	/**
	 * Creates a new ML-DSA signer.
	 *
	 * @param keyPair The ML-DSA key pair. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key pair is invalid.
	 */
	public MLDSASigner(final KeyPair keyPair)
		throws JOSEException {

		this(keyPair, Collections.<JWSSignerOption>emptySet());
	}


	/**
	 * Creates a new ML-DSA signer.
	 *
	 * @param keyPair The ML-DSA key pair. Must not be {@code null}.
	 * @param opts    The signing options, empty or {@code null} if none.
	 *
	 * @throws JOSEException If the key pair is invalid.
	 */
	public MLDSASigner(final KeyPair keyPair, final Set<JWSSignerOption> opts)
		throws JOSEException {

		this(new MLDSAKey(keyPair), opts);
	}


	/**
	 * Creates a new ML-DSA signer from a private key.
	 *
	 * <p>This constructor is intended for private keys that expose enough
	 * material to derive the corresponding public key, either directly or
	 * via their PKCS#8 encoding.
	 *
	 * @param privateKey The ML-DSA private key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key is invalid or its public key cannot
	 *                       be derived.
	 */
	public MLDSASigner(final PrivateKey privateKey)
		throws JOSEException {

		this(privateKey, Collections.<JWSSignerOption>emptySet());
	}


	/**
	 * Creates a new ML-DSA signer from a private key.
	 *
	 * <p>This constructor is intended for private keys that expose enough
	 * material to derive the corresponding public key, either directly or
	 * via their PKCS#8 encoding.
	 *
	 * @param privateKey The ML-DSA private key. Must not be {@code null}.
	 * @param opts       The signing options, empty or {@code null} if none.
	 *
	 * @throws JOSEException If the key is invalid or its public key cannot
	 *                       be derived.
	 */
	public MLDSASigner(final PrivateKey privateKey, final Set<JWSSignerOption> opts)
		throws JOSEException {

		this(new MLDSAKey(privateKey, derivePublicKey(privateKey)), opts);
	}


	/**
	 * Creates a new ML-DSA signer.
	 *
	 * @param privateKey The ML-DSA private key. Must not be {@code null}.
	 * @param publicKey  The ML-DSA public key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the keys are invalid.
	 */
	public MLDSASigner(final PrivateKey privateKey, final PublicKey publicKey)
		throws JOSEException {

		this(privateKey, publicKey, Collections.<JWSSignerOption>emptySet());
	}


	/**
	 * Creates a new ML-DSA signer.
	 *
	 * @param privateKey The ML-DSA private key. Must not be {@code null}.
	 * @param publicKey  The ML-DSA public key. Must not be {@code null}.
	 * @param opts       The signing options, empty or {@code null} if none.
	 *
	 * @throws JOSEException If the keys are invalid.
	 */
	public MLDSASigner(final PrivateKey privateKey, final PublicKey publicKey, final Set<JWSSignerOption> opts)
		throws JOSEException {

		this(new MLDSAKey(privateKey, publicKey), opts);
	}


	/**
	 * Creates a new ML-DSA signer.
	 *
	 * @param privateKey The ML-DSA private JWK. Must not be
	 *                   {@code null} and must contain a private part.
	 *
	 * @throws JOSEException If the key is not private.
	 */
	public MLDSASigner(final MLDSAKey privateKey)
		throws JOSEException {

		this(privateKey, Collections.<JWSSignerOption>emptySet());
	}


	/**
	 * Creates a new ML-DSA signer.
	 *
	 * @param privateKey The ML-DSA private JWK. Must not be
	 *                   {@code null} and must contain a private part.
	 * @param opts       The signing options, empty or {@code null} if none.
	 *
	 * @throws JOSEException If the key is not private.
	 */
	public MLDSASigner(final MLDSAKey privateKey, final Set<JWSSignerOption> opts)
		throws JOSEException {

		if (privateKey == null) {
			throw new IllegalArgumentException("The ML-DSA private key must not be null");
		}

		if (! privateKey.isPrivate()) {
			throw new JOSEException("The MLDSAKey doesn't contain a private part");
		}

		this.privateKey = privateKey;
		this.opts = opts != null ? opts : Collections.<JWSSignerOption>emptySet();
	}


	/**
	 * Returns the ML-DSA private key.
	 *
	 * @return The ML-DSA private key.
	 */
	public MLDSAKey getPrivateKey() {

		return privateKey;
	}


	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException {

		return sign(header, new ByteArrayJWSInput(signingInput));
	}


	@Override
	public Base64URL sign(final JWSHeader header, final JWSInput jwsInput)
		throws JOSEException {

		final Signature signer = getInitiatedSignature(header);

		if (opts.contains(UserAuthenticationRequired.getInstance())) {
			throw new ActionRequiredForJWSCompletionException(
				"Authenticate user to complete signing",
				UserAuthenticationRequired.getInstance(),
				new CompletableJWSObjectSigning() {
					@Override
					public Signature getInitializedSignature() {
						return signer;
					}

					@Override
					public Base64URL complete()
						throws JOSEException {

						return sign(jwsInput, signer);
					}
				}
			);
		}

		return sign(jwsInput, signer);
	}


	private Signature getInitiatedSignature(final JWSHeader header)
		throws JOSEException {

		final JWSAlgorithm alg = header.getAlgorithm();

		if (! supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(
				AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}

		final JWSAlgorithm keyAlg = (JWSAlgorithm)privateKey.getAlgorithm();
		if (! keyAlg.equals(alg)) {
			throw new JOSEException(
				String.format(
					"ML-DSA JWS algorithm mismatch: header=%s key=%s",
					alg.getName(),
					keyAlg.getName()
				)
			);
		}

		try {
			final Provider jcaContextProvider = getJCAContext().getProvider();
			final Provider provider =
				jcaContextProvider != null ?
					jcaContextProvider :
					privateKey.getKeyStore() != null ? privateKey.getKeyStore().getProvider() : null;
			final PrivateKey signingKey = privateKey.toPrivateKey();

			final Signature signer = MLDSA.getSignerAndVerifier(alg, provider);
			signer.initSign(
				signingKey != null && signingKey.getEncoded() == null ?
					signingKey :
					privateKey.toMLDSAPrivateKey(provider),
				getJCAContext().getSecureRandom());
			return signer;

		} catch (InvalidKeyException e) {
			throw new JOSEException("Invalid ML-DSA private key: " + e.getMessage(), e);
		} catch (GeneralSecurityException | RuntimeException e) {
			throw new JOSEException(e.getMessage(), e);
		}
	}


	private Base64URL sign(final JWSInput jwsInput, final Signature signer)
		throws JOSEException {

		try {
			jwsInput.apply(signer);
			return Base64URL.encode(signer.sign());
		} catch (SignatureException e) {
			throw new JOSEException(e.getMessage(), e);
		}
	}


	private static PublicKey derivePublicKey(final PrivateKey privateKey)
		throws JOSEException {

		if (privateKey == null) {
			throw new IllegalArgumentException("The ML-DSA private key must not be null");
		}

		if (privateKey instanceof MLDSAPrivateKey) {
			return ((MLDSAPrivateKey)privateKey).getPublicKey();
		}

		byte[] encoded = privateKey.getEncoded();
		if (encoded == null || encoded.length == 0) {
			throw new JOSEException("The ML-DSA private key must expose a public key or PKCS#8 encoding");
		}

		try {
			KeyFactory keyFactory = KeyFactory.getInstance("ML-DSA", BouncyCastleProviderSingleton.getInstance());
			PrivateKey resolvedPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));

			if (resolvedPrivateKey instanceof MLDSAPrivateKey) {
				return ((MLDSAPrivateKey)resolvedPrivateKey).getPublicKey();
			}

			throw new JOSEException(
				"Provider returned unsupported ML-DSA private key implementation: " +
					resolvedPrivateKey.getClass().getName()
			);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new JOSEException(e.getMessage(), e);
		}
	}
}
