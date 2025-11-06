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


import java.util.HashSet;
import java.util.Set;

/**
 * Collection utilities.
 */
public class CollectionUtils {


        /**
         * Returns {@code true} if the specified set contains {@code null}.
         * Prevents a NPE when calling {@code Set.contains(null)} on a
         * {@code Java 9 Set.of()}.
         *
         * @param set The set. Must not be {@code null}.
         *
         * @return {@code true} if the set contains {@code null}, else
         *         {@code false}.
         */
        public static <T> boolean containsNull(final Set<T> set) {
                HashSet<T> defensiveCopy = new HashSet<>(set);
                return defensiveCopy.contains(null);
        }


        /**
         * Prevents public instantiation.
         */
        private CollectionUtils() {
        }
}
