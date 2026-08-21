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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.crypto.impl.ECDHCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.XWingKey;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;


/**
 * PQEID: X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768) encrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects}. Replaces
 * {@link ECDHEncrypter}/{@link X25519Encrypter} in this fork - see
 * {@link com.nimbusds.jose.crypto.impl.ECDH#resolveAlgorithmMode}, which now
 * resolves {@link JWEAlgorithm#XWING} instead of {@link JWEAlgorithm#ECDH_ES}
 * for "direct" mode key agreement.
 *
 * <p>Reuses {@link ECDHCryptoProvider}'s {@code encryptWithZ} (concat KDF-based
 * CEK derivation + content encryption) with the X-Wing KEM shared secret
 * standing in for the ECDH shared secret "Z". Unlike plain ECDH-ES, a KEM is
 * asymmetric: the encapsulated ciphertext produced by
 * {@link XWingKEMGenerator} must travel to the recipient, so (unlike
 * ECDH-ES, where the JWE "encrypted key" part is empty) it is carried in the
 * "encrypted key" part here - the same field RSA-OAEP/AES-KW use for their
 * own wrapped/encapsulated key material.
 *
 * <p><strong>Not a standard/registered JOSE algorithm</strong> - see
 * {@link JWEAlgorithm#XWING}.
 *
 * <p>This class is thread-safe.
 */
@ThreadSafe
public class XWingEncrypter extends ECDHCryptoProvider implements JWEEncrypter {


	/**
	 * PQEID: placeholder curve identifier - X-Wing is not an elliptic
	 * curve in the JWK "crv" sense, but {@link ECDHCryptoProvider}'s
	 * constructor requires a {@link Curve} it can validate against
	 * {@link #supportedEllipticCurves()}.
	 */
	public static final Curve CURVE = new Curve("XWING");


	private static final Set<Curve> SUPPORTED_ELLIPTIC_CURVES = Collections.singleton(CURVE);


	private static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = Collections.singleton(JWEAlgorithm.XWING);


	private final XWingPublicKeyParameters recipientPublicKey;


	/**
	 * Creates a new X-Wing encrypter.
	 *
	 * @param recipientPublicKey The recipient's public X-Wing JWK. Must
	 *                           not be {@code null}.
	 *
	 * @throws JOSEException If the key couldn't be used.
	 */
	public XWingEncrypter(final XWingKey recipientPublicKey)
		throws JOSEException {

		super(CURVE, null);

		this.recipientPublicKey = recipientPublicKey.toBCPublicKeyParameters();
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
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText, final byte[] aad)
		throws JOSEException {

		// PQEID: X-Wing encapsulation - generates the KEM shared secret ("Z")
		// and the ciphertext ("encrypted key") in one step, unlike ECDH-ES
		// where an ephemeral key pair is generated and Z is derived
		// separately via a DH agreement.
		XWingKEMGenerator kemGenerator = new XWingKEMGenerator(new SecureRandom());
		SecretWithEncapsulation encapsulated = kemGenerator.generateEncapsulated(recipientPublicKey);

		SecretKey Z = new SecretKeySpec(encapsulated.getSecret(), "AES");
		Base64URL encapsulationCiphertext = Base64URL.encode(encapsulated.getEncapsulation());

		JWECryptoParts parts = encryptWithZ(header, Z, clearText, aad);

		// PQEID: encryptWithZ leaves encryptedKey null (DIRECT mode, same as
		// plain ECDH-ES) - overwrite it with the X-Wing KEM ciphertext, which
		// the recipient needs to decapsulate the shared secret.
		return new JWECryptoParts(
			parts.getHeader(),
			encapsulationCiphertext,
			parts.getInitializationVector(),
			parts.getCipherText(),
			parts.getAuthenticationTag());
	}


	/**
	 * Encrypts the specified clear text of a {@link com.nimbusds.jose.JWEObject JWE object}.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must specify
	 *                  a supported JWE algorithm and method. Must not be
	 *                  {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 *
	 * @return The resulting JWE crypto parts.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported or if encryption failed for some
	 *                       other internal reason.
	 */
	@Deprecated
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		return encrypt(header, clearText, AAD.compute(header));
	}
}
