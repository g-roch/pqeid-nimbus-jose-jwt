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

package com.nimbusds.jose.proc;


import com.nimbusds.jose.jwk.source.JWKSource;
import net.jcip.annotations.ThreadSafe;

import java.util.Objects;


/**
 * Abstract JSON Web Key (JWK) selector with source.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-04-20
 */
@ThreadSafe
abstract class AbstractJWKSelectorWithSource <C extends SecurityContext> {
	

	/**
	 * The JWK source.
	 */
	private final JWKSource<C> jwkSource;


	/**
	 * Creates a new abstract JWK selector with a source.
	 *
	 * @param jwkSource The JWK source. Must not be {@code null}.
	 */
	public AbstractJWKSelectorWithSource(final JWKSource<C> jwkSource) {
		this.jwkSource = Objects.requireNonNull(jwkSource);
	}


	/**
	 * Returns the JWK source.
	 *
	 * @return The JWK source.
	 */
	public JWKSource<C> getJWKSource() {
		return jwkSource;
	}
}
