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

package com.nimbusds.jose.crypto;


import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.CriticalHeaderParamsDeferral;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.XWingKey;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Collections;
import java.util.Set;


/**
 * PQEID: X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768) decrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects}. Counterpart of
 * {@link XWingEncrypter} - see that class for the overall design rationale
 * (replaces {@link ECDHDecrypter}/{@link X25519Decrypter} in this fork).
 *
 * <p>Reuses {@link ECDHCryptoProvider}'s {@code decryptWithZ} with the
 * X-Wing KEM shared secret standing in for the ECDH shared secret "Z",
 * decapsulated from the JWE "encrypted key" part via
 * {@link XWingKEMExtractor}.
 */
public class XWingDecrypter extends ECDHCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	private static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES = Collections.singleton(XWingEncrypter.CURVE);


	private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Collections.singleton(JWEAlgorithm.XWING);


	private final XWingPrivateKeyParameters recipientPrivateKey;


	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new X-Wing decrypter.
	 *
	 * @param recipientPrivateKey The recipient's private X-Wing JWK. Must
	 *                            contain a private part, must not be
	 *                            {@code null}.
	 *
	 * @throws JOSEException If the key couldn't be used.
	 */
	public XWingDecrypter(final XWingKey recipientPrivateKey)
		throws JOSEException {

		this(recipientPrivateKey, null);
	}


	/**
	 * Creates a new X-Wing decrypter.
	 *
	 * @param recipientPrivateKey The recipient's private X-Wing JWK. Must
	 *                            contain a private part, must not be
	 *                            {@code null}.
	 * @param defCritHeaders      The names of the critical header
	 *                            parameters that are deferred to the
	 *                            application for processing, empty set or
	 *                            {@code null} if none.
	 *
	 * @throws JOSEException If the key couldn't be used.
	 */
	public XWingDecrypter(final XWingKey recipientPrivateKey, final Set<String> defCritHeaders)
		throws JOSEException {

		super(XWingEncrypter.CURVE, null);

		this.recipientPrivateKey = recipientPrivateKey.toBCPrivateKeyParameters();
		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	@Override
	public Set<Curve> supportedEllipticCurves() {

		return SUPPORTED_ELLIPTIC_CURVES;
	}


	@Override
	public Set<JWEAlgorithm> supportedJWEAlgorithms() {

		return SUPPORTED_ALGORITHMS;
	}


	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getDeferredCriticalHeaderParams();
	}


	@Override
	public byte[] decrypt(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authTag,
			      final byte[] aad)
		throws JOSEException {

		critPolicy.ensureHeaderPasses(header);

		if (encryptedKey == null) {
			throw new JOSEException("Missing JWE encrypted key (X-Wing KEM encapsulation)");
		}

		XWingKEMExtractor kemExtractor = new XWingKEMExtractor(recipientPrivateKey);
		byte[] secret = kemExtractor.extractSecret(encryptedKey.decode());
		SecretKey Z = new SecretKeySpec(secret, "AES");

		return decryptWithZ(header, aad, Z, encryptedKey, iv, cipherText, authTag);
	}


	/**
	 * Decrypts the specified cipher text of a {@link com.nimbusds.jose.JWEObject JWE
	 * Object}.
	 *
	 * @param header       The JSON Web Encryption (JWE) header. Must
	 *                     specify a supported JWE algorithm and method.
	 *                     Must not be {@code null}.
	 * @param encryptedKey The encrypted key (X-Wing KEM ciphertext). Must
	 *                     not be {@code null}.
	 * @param iv           The initialisation vector, {@code null} if not
	 *                     required by the JWE algorithm.
	 * @param cipherText   The cipher text to decrypt. Must not be
	 *                     {@code null}.
	 * @param authTag      The authentication tag, {@code null} if not
	 *                     required.
	 *
	 * @return The clear text.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported, if a critical header parameter is
	 *                       not supported or marked for deferral to the
	 *                       application, or if decryption failed for some
	 *                       other reason.
	 */
	@Deprecated
	public byte[] decrypt(final JWEHeader header,
			      final Base64URL encryptedKey,
			      final Base64URL iv,
			      final Base64URL cipherText,
			      final Base64URL authTag)
		throws JOSEException {

		return decrypt(header, encryptedKey, iv, cipherText, authTag, AAD.compute(header));
	}
}
