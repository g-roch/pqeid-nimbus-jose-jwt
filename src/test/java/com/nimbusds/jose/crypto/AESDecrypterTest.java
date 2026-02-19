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

package com.nimbusds.jose.crypto;

import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class AESDecrypterTest {


        @Test
        public void testDeferredParams() throws Exception {

                Set<String> deferred = new HashSet<>(Arrays.asList("exp", "iat"));

                byte[] key = new byte[16]; // 128-bit AES key
                new java.security.SecureRandom().nextBytes(key);
                AESDecrypter decrypter = new AESDecrypter(new SecretKeySpec(key, "AES"), deferred);

                assertEquals(deferred, decrypter.getDeferredCriticalHeaderParams());
                assertEquals(Collections.singleton("b64"), decrypter.getProcessedCriticalHeaderParams());
                assertNotEquals(decrypter.getProcessedCriticalHeaderParams(), decrypter.getDeferredCriticalHeaderParams());
        }
}
