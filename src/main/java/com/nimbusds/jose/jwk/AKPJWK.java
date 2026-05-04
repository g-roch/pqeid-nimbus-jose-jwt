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

package com.nimbusds.jose.jwk;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;

import java.net.URI;
import java.security.KeyStore;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;


/**
 * Algorithm key pair JSON Web Key (JWK).
 *
 * <p>This is a minimal abstract base for JWKs using the generic
 * {@code kty=AKP} shape with {@code pub}/{@code priv} members.
 *
 * @author Robert Stupp
 * @version 2026-05-04
 */
public abstract class AKPJWK extends JWK implements AsymmetricJWK {


	private static final long serialVersionUID = 1L;


	/**
	 * The JSON Web Key type value.
	 */
	public static final KeyType KEY_TYPE = KeyType.AKP;


	/**
	 * The public key member name.
	 */
	protected static final String PUBLIC_KEY_PARAMETER = "pub";


	/**
	 * The private key member name.
	 */
	protected static final String PRIVATE_KEY_PARAMETER = "priv";


	/**
	 * Creates a new algorithm key pair JWK.
	 *
	 * @param use        The key use, {@code null} if not specified.
	 * @param ops        The key operations, {@code null} if not specified.
	 * @param alg        The intended JOSE algorithm for the key. Must not be
	 *                   {@code null}.
	 * @param kid        The key ID, {@code null} if not specified.
	 * @param x5u        The X.509 certificate URL, {@code null} if not
	 *                   specified.
	 * @param x5t        The X.509 certificate thumbprint, {@code null} if not
	 *                   specified.
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
	 * @param ks         Reference to the underlying key store,
	 *                   {@code null} if none.
	 */
	protected AKPJWK(final KeyUse use,
			 final Set<KeyOperation> ops,
			 final Algorithm alg,
			 final String kid,
			 final URI x5u,
			 final Base64URL x5t,
			 final Base64URL x5t256,
			 final List<Base64> x5c,
			 final Date exp,
			 final Date nbf,
			 final Date iat,
			 final KeyRevocation revocation,
			 final KeyStore ks) {

		super(
			KEY_TYPE,
			use,
			ops,
			Objects.requireNonNull(alg, JWKParameterNames.ALGORITHM),
			kid,
			x5u,
			x5t,
			x5t256,
			x5c,
			exp,
			nbf,
			iat,
			revocation,
			ks
		);
	}


	@Override
	public LinkedHashMap<String, ?> getRequiredParams() {

		LinkedHashMap<String, Object> params = new LinkedHashMap<>();
		params.put(JWKParameterNames.ALGORITHM, getAlgorithm().getName());
		params.put(JWKParameterNames.KEY_TYPE, KEY_TYPE.getValue());
		params.put(PUBLIC_KEY_PARAMETER, encodedPublicData().toString());
		return params;
	}


	@Override
	public Map<String, Object> toJSONObject() {

		Map<String, Object> json = super.toJSONObject();
		json.put(PUBLIC_KEY_PARAMETER, encodedPublicData().toString());

		Base64URL privateEncoded = encodedPrivateData();
		if (privateEncoded != null) {
			json.put(PRIVATE_KEY_PARAMETER, privateEncoded.toString());
		}

		return json;
	}


	protected abstract Base64URL encodedPublicData();


	protected abstract Base64URL encodedPrivateData();
}
