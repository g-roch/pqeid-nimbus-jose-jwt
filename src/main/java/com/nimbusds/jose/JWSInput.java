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

import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.Mac;


/**
 * Represents the JWS input to a digital signature or MAC computation.
 *
 * @author Joost Koehoorn
 * @version 2026-04-02
 * @since 11.0
 */
public interface JWSInput {


        /**
         * Returns this JWS input as a string.
         *
         * @return The string representation.
         */
        String toString();


        /**
         * Returns this JWS input as a byte array.
         *
         * @return The byte array representation.
         */
        byte[] toByteArray();


        /**
         * Applies this JWS input to the specified signature.
         *
         * @param signature The signature to update with this JWS input. Must
         *                  not be {@code null}.
         *
         * @throws SignatureException If the specified signature was not
         *                            initialised properly.
         */
        default void apply(final Signature signature) throws SignatureException {

                signature.update(toByteArray());
        }


        /**
         * Applies this JWS input to the specified MAC instance.
         *
         * @param mac The MAC to update with this JWS input. Must not be
         *            {@code null}.
         */
        default void apply(final Mac mac) {

                mac.update(toByteArray());
        }
}
