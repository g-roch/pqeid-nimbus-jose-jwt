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
import junit.framework.TestCase;


public class MaxCompressedCipherTextLengthTest extends TestCase {


	public void testConstructorAndGetter() {

		MaxCompressedCipherTextLength opt = new MaxCompressedCipherTextLength(500_000);

		assertTrue(opt instanceof JWEDecrypterOption);
		assertEquals(500_000, opt.getMaxLength());
		assertEquals("MaxCompressedCipherTextLength(500000)", opt.toString());
	}


	public void testRejectZeroLength() {

		try {
			new MaxCompressedCipherTextLength(0);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The max compressed cipher text length must be a positive integer", e.getMessage());
		}
	}


	public void testRejectNegativeLength() {

		try {
			new MaxCompressedCipherTextLength(-1);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The max compressed cipher text length must be a positive integer", e.getMessage());
		}
	}
}
