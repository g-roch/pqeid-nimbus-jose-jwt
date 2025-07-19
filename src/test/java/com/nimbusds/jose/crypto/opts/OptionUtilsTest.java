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


import com.nimbusds.jose.JWEDecrypterOption;
import com.nimbusds.jose.JWSSignerOption;
import junit.framework.TestCase;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


public class OptionUtilsTest extends TestCase {


	public void testJWSSignerOptionIsPresent_true() {
		
		assertTrue(OptionUtils.optionIsPresent(Collections.<JWSSignerOption>singleton(UserAuthenticationRequired.getInstance()), UserAuthenticationRequired.class));
		
		Set<JWSSignerOption> opts = new HashSet<>();
		opts.add(AllowWeakRSAKey.getInstance());
		opts.add(UserAuthenticationRequired.getInstance());
		opts.add(new JWSSignerOption() {});
		
		assertTrue(OptionUtils.optionIsPresent(opts, UserAuthenticationRequired.class));
	}


	public void testJWSSignerOptionIsPresent_false() {
		
		assertFalse(OptionUtils.optionIsPresent(null, UserAuthenticationRequired.class));
		assertFalse(OptionUtils.optionIsPresent(Collections.<JWSSignerOption>emptySet(), UserAuthenticationRequired.class));
		assertFalse(OptionUtils.optionIsPresent(Collections.<JWSSignerOption>singleton(AllowWeakRSAKey.getInstance()), UserAuthenticationRequired.class));
		
		Set<JWSSignerOption> opts = new HashSet<>();
		opts.add(AllowWeakRSAKey.getInstance());
		opts.add(new JWSSignerOption() {});
		
		assertFalse(OptionUtils.optionIsPresent(opts, UserAuthenticationRequired.class));
	}


	public void testJWEDecrypterOptionIsPresent_true() {

		assertTrue(OptionUtils.optionIsPresent(Collections.<JWEDecrypterOption>singleton(AllowWeakRSAKey.getInstance()), AllowWeakRSAKey.class));

		Set<JWEDecrypterOption> opts = new HashSet<>();
		opts.add(AllowWeakRSAKey.getInstance());
		opts.add(new JWEDecrypterOption() {});

		assertTrue(OptionUtils.optionIsPresent(opts, AllowWeakRSAKey.class));
	}


	public void testJWEDecrypterOptionIsPresent_false() {

		assertFalse(OptionUtils.optionIsPresent(null, AllowWeakRSAKey.class));
		assertFalse(OptionUtils.optionIsPresent(Collections.<JWEDecrypterOption>emptySet(), AllowWeakRSAKey.class));

		Set<JWEDecrypterOption> opts = new HashSet<>();
		opts.add(new JWEDecrypterOption() {});

		assertFalse(OptionUtils.optionIsPresent(opts, AllowWeakRSAKey.class));
	}
}
