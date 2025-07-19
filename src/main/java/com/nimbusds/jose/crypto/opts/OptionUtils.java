/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2025, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.JWSSignerOption;
import com.nimbusds.jose.Option;
import com.nimbusds.jose.crypto.impl.RSAKeyUtils;

import java.security.PrivateKey;
import java.util.Set;

import static com.nimbusds.jose.jwk.gen.RSAKeyGenerator.MIN_KEY_SIZE_BITS;


/**
 * Utilities for processing JOSE options.
 *
 * @author Vladimir Dzhuvinov
 * @version 2025-07-17
 */
public class OptionUtils {
	
	
	/**
	 * Returns {@code true} if the specified set of options contains an
	 * instance of a class implementing {@link JWSSignerOption}.
	 *
	 * @param opts   The options set, may be {@code null}.
	 * @param tClass The class. Must not be {@code null}.
	 *
	 * @return {@code true} if an option is present, else {@code false}.
	 */
	@Deprecated
	public static <T extends Option> boolean optionIsPresent(final Set<? extends Option> opts, final Class<T> tClass) {
		
		if (opts == null || opts.isEmpty()) {
			return false;
		}
		
		for (Option o: opts) {
			if (o.getClass().isAssignableFrom(tClass)) {
				return true;
			}
		}
		
		return false;
	}


	/**
	 * Throws an {@link IllegalArgumentException} if the size of the
	 * specified RSA private key shorter than the minimum required.
	 *
	 * @param privateKey The RSA private key. Must not be {@code null}.
	 * @param opts       The options. Must not be {@code null}.
	 */
	public static void ensureMinRSAPrivateKeySize(final PrivateKey privateKey, final Set<? extends Option> opts) {

		if (! opts.contains(AllowWeakRSAKey.getInstance())) {

			int keyBitLength = RSAKeyUtils.keyBitLength(privateKey);

			if (keyBitLength > 0 && keyBitLength < MIN_KEY_SIZE_BITS) {
				throw new IllegalArgumentException("The RSA key size must be at least " + MIN_KEY_SIZE_BITS + " bits");
			}
		}
	}
}
