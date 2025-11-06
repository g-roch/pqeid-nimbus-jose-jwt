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

package com.nimbusds.jose.util;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class CollectionUtilsTest {


        @Test
        public void containsNull_false() {

                assertFalse(CollectionUtils.containsNull(new HashSet<>(Arrays.asList("a", "b"))));
                assertFalse(CollectionUtils.containsNull(Collections.emptySet()));
        }


        @Test
        public void containsNull_false_simulateJava9SetOf() {

                HashSet<String> setToBeDefensivelyCopied = new HashSet<String>() {
                        @Override
                        public boolean contains(Object o) {
                                throw new NullPointerException("Simulate Java 9 Set.of() behaviour");
                        }
                };

                assertFalse(CollectionUtils.containsNull(setToBeDefensivelyCopied));
        }


        @Test
        public void containsNull_true() {

                assertTrue(CollectionUtils.containsNull(new HashSet<>(Arrays.asList("a", null))));
                assertTrue(CollectionUtils.containsNull(Collections.singleton(null)));
        }
}