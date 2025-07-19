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
import com.nimbusds.jose.JWEEncrypterOption;
import net.jcip.annotations.Immutable;

import javax.crypto.Cipher;


/**
 * JCA cipher mode.
 *
 * @author Vladimir Dzhuvinov
 * @version 2025-07-19
 */
@Immutable
public final class CipherMode implements JWEEncrypterOption, JWEDecrypterOption {


	/**
	 * {@link Cipher#UNWRAP_MODE} / {@link Cipher#UNWRAP_MODE}. The default
	 * for {@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP},
	 * {@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256} and
	 * {@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_512}.
	 */
	public static final CipherMode WRAP_UNWRAP = new CipherMode(Cipher.WRAP_MODE, Cipher.UNWRAP_MODE);


	/**
	 * {@link Cipher#ENCRYPT_MODE} / {@link Cipher#DECRYPT_MODE}.
	 */
	public static final CipherMode ENCRYPT_DECRYPT = new CipherMode(Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE);



	private final int modeForEncryption;


	private final int modeForDecryption;


	private CipherMode(final int modeForEncryption, final int modeForDecryption) {
		this.modeForEncryption = modeForEncryption;
		this.modeForDecryption = modeForDecryption;
	}


	/**
	 * Returns the cipher mode for a JWE encrypter.
	 *
	 * @return The cipher mode.
	 */
	public int getForJWEEncrypter() {
		return modeForEncryption;
	}


	/**
	 * Returns the cipher mode for a JWE decrypter.
	 *
	 * @return The cipher mode.
	 */
	public int getForJWEDecrypter() {
		return modeForDecryption;
	}


	@Override
	public String toString() {
		return "CipherMode [forEncryption=" + modeForEncryption + ", forDecryption=" + modeForDecryption + "]";
	}
}
