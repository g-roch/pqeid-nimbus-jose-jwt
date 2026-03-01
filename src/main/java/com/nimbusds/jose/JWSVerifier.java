/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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


import com.nimbusds.jose.util.Base64URL;
import java.security.Signature;


/**
 * JSON Web Signature (JWS) verifier.
 *
 * @author Vladimir Dzhuvinov
 * @version 2015-04-21
 */
public interface JWSVerifier extends JWSProvider {


	/**
	 * Verifies the specified {@link JWSObject#getSignature signature} of a
	 * {@link JWSObject JWS object}.
	 *
	 * @param header       The JSON Web Signature (JWS) header. Must
	 *                     specify a supported JWS algorithm and must not
	 *                     be {@code null}.
	 * @param signingInput The signing input. Must not be {@code null}.
	 * @param signature    The signature part of the JWS object. Must not
	 *                     be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully verified, 
	 *         {@code false} if the signature is invalid or if a critical
	 *         header is neither supported nor marked for deferral to the
	 *         application.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported, or if
	 *                       signature verification failed for some other
	 *                       internal reason.
	 */
	boolean verify(final JWSHeader header, final byte[] signingInput, final Base64URL signature)
		throws JOSEException;


	/**
	 * Verifies the specified {@link JWSObject#getSignature signature} of a
	 * {@link JWSObject JWS object}.
	 *
	 * <p>The default implementation of this overload calls
	 * {@link #verify(JWSHeader, byte[], Base64URL)} using
	 * {@link SigningInput#toByteArray()}. Implementors of this interface may
	 * avoid materializing the signing input into a byte array by implementing
	 * this overload and using {@link SigningInput#apply(Signature)} to allow
	 * the signing input to feed its bytes into a {@link Signature} in chunks.
	 *
	 * @param header       The JSON Web Signature (JWS) header. Must
	 *                     specify a supported JWS algorithm and must not
	 *                     be {@code null}.
	 * @param signingInput The signing input. Must not be {@code null}.
	 * @param signature    The signature part of the JWS object. Must not
	 *                     be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully verified,
	 *         {@code false} if the signature is invalid or if a critical
	 *         header is neither supported nor marked for deferral to the
	 *         application.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported, or if
	 *                       signature verification failed for some other
	 *                       internal reason.
	 *
	 * @since 11.0
	 */
	default boolean verify(final JWSHeader header, final SigningInput signingInput, final Base64URL signature)
		throws JOSEException {

		return verify(header, signingInput.toByteArray(), signature);
	}
}
