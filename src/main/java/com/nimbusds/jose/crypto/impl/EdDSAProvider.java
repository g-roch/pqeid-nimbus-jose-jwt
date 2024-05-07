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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * The base abstract class for Edwards-curve Digital Signature Algorithm 
 * (EdDSA) signers and validators of {@link com.nimbusds.jose.JWSObject JWS 
 * objects}.
 *
 * <p>Supports the following algorithm:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#Ed25519}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#EdDSA} with
 *         {@link com.nimbusds.jose.jwk.Curve#Ed25519}
 * </ul>
 * 
 * @author Tim McLean
 * @version 2024-05-07
 */
public abstract class EdDSAProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the EdDSA provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	/**
	 * The supported curves by the EdDSA provider class.
	 */
	public static final Set<Curve> SUPPORTED_CURVES;


	static {
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(
			new HashSet<>(
				Arrays.asList(
					JWSAlgorithm.EdDSA,
					JWSAlgorithm.Ed25519
				)
			));

		SUPPORTED_CURVES = Collections.singleton(Curve.Ed25519);
	}


	/**
	 * Creates a new Edwards-curve Digital Signature Algorithm (EdDSA) 
	 * provider.
	 */
	protected EdDSAProvider() {

		super(SUPPORTED_ALGORITHMS);
	}
}

