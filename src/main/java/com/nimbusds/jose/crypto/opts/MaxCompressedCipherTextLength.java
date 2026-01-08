/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto.opts;


import com.nimbusds.jose.JWEDecrypterOption;
import net.jcip.annotations.Immutable;


/**
 * JSON Web Encryption (JWE) decrypter option to configure the maximum allowed
 * length of compressed cipher text. The
 * {@link com.nimbusds.jose.JWEObject#MAX_COMPRESSED_CIPHER_TEXT_LENGTH default}
 * is 100 thousand characters.
 *
 * @author Vladimir Dzhuvinov
 * @version 2025-01-04
 */
@Immutable
public final class MaxCompressedCipherTextLength implements JWEDecrypterOption {


	private final int maxLength;


	/**
	 * Creates a new maximum compressed cipher text length option.
	 *
	 * @param maxLength The maximum allowed length, in characters. Must be
	 *                  positive.
	 */
	public MaxCompressedCipherTextLength(final int maxLength) {
		if (maxLength <= 0) {
			throw new IllegalArgumentException("The max compressed cipher text length must be a positive integer");
		}
		this.maxLength = maxLength;
	}


	/**
	 * Returns the maximum allowed compressed cipher text length.
	 *
	 * @return The maximum length, in characters.
	 */
	public int getMaxLength() {
		return maxLength;
	}


	@Override
	public String toString() {
		return "MaxCompressedCipherTextLength(" + maxLength + ")";
	}
}
