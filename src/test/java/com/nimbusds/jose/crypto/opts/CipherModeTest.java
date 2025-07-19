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

import com.nimbusds.jose.Option;
import org.junit.Test;

import javax.crypto.Cipher;

import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;


public class CipherModeTest {


        @Test
        public void constant_WRAP_UNWRAP() {

                assertEquals(Cipher.WRAP_MODE, CipherMode.WRAP_UNWRAP.getForJWEEncrypter());
                assertEquals(Cipher.UNWRAP_MODE, CipherMode.WRAP_UNWRAP.getForJWEDecrypter());
                assertEquals("CipherMode [forEncryption=3, forDecryption=4]", CipherMode.WRAP_UNWRAP.toString());

                Set<Option> opts = new HashSet<>();
                opts.add(CipherMode.WRAP_UNWRAP);
                assertTrue(opts.contains(CipherMode.WRAP_UNWRAP));
        }


        @Test
        public void constant_ENCRYPT_DECRYPT() {

                assertEquals(Cipher.ENCRYPT_MODE, CipherMode.ENCRYPT_DECRYPT.getForJWEEncrypter());
                assertEquals(Cipher.DECRYPT_MODE, CipherMode.ENCRYPT_DECRYPT.getForJWEDecrypter());
                assertEquals("CipherMode [forEncryption=1, forDecryption=2]", CipherMode.ENCRYPT_DECRYPT.toString());

                Set<Option> opts = new HashSet<>();
                opts.add(CipherMode.ENCRYPT_DECRYPT);
                assertTrue(opts.contains(CipherMode.ENCRYPT_DECRYPT));
        }
}