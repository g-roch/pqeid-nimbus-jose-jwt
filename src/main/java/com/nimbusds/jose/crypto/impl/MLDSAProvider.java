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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JWSAlgorithm;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * The base abstract class for ML-DSA signers and verifiers of
 * {@link com.nimbusds.jose.JWSObject JWS objects}.
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
public abstract class MLDSAProvider extends BaseJWSProvider {


	/**
	 * The supported JWS algorithms by the ML-DSA provider class.
	 */
	public static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS;


	static {
		Set<JWSAlgorithm> algs = new LinkedHashSet<>();
		algs.add(JWSAlgorithm.ML_DSA_44);
		algs.add(JWSAlgorithm.ML_DSA_65);
		algs.add(JWSAlgorithm.ML_DSA_87);
		SUPPORTED_ALGORITHMS = Collections.unmodifiableSet(algs);
	}


	/**
	 * Creates a new ML-DSA provider.
	 */
	protected MLDSAProvider() {

		super(SUPPORTED_ALGORITHMS);
	}
}
