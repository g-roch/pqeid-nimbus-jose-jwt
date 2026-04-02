/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2026, Connect2id Ltd.
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
package com.nimbusds.jose;

import com.nimbusds.jose.util.StandardCharset;

import java.util.Objects;


/**
 * JWS input precomposed from a byte array representation of a JWS header and
 * payload, concatenated by a dot.
 *
 * @author Joost Koehoorn
 * @version 2026-04-02
 * @since 11.0
 */
public final class ByteArrayJWSInput implements JWSInput {


        private final byte[] signingInput;


        /**
         * Creates a JWS input from a precomposed byte array.
         *
         * @param signingInput The byte array. Must not be {@code null}.
         */
        public ByteArrayJWSInput(final byte[] signingInput) {

                this.signingInput = Objects.requireNonNull(signingInput);
        }


        @Override
        public String toString() {

                return new String(signingInput, StandardCharset.UTF_8);
        }


        @Override
        public byte[] toByteArray() {

                return signingInput;
        }
}
