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

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;

import java.nio.ByteBuffer;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;
import javax.crypto.Mac;


/**
 * JWS input composed of a {@link JWSHeader} and a {@link Payload}. The
 * {@link JWSInput#apply(Signature)} and {@link JWSInput#apply(Mac)} methods
 * feed the JWS input efficiently, avoiding serialisation of the input into a
 * temporary byte array.
 *
 * <p>This is especially efficient for {@link Payload}s created with
 * {@link Payload#Payload(byte[])} using the {@code b64} JWS header (see
 * {@link JWSHeader#isBase64URLEncodePayload()}).
 *
 * @author Joost Koehoorn
 * @version 2026-04-02
 * @since 11.0
 */
public final class ComposedJWSInput implements JWSInput {


        private final Base64URL header;
        private final Payload payload;
        private final boolean base64URLEncodePayload;


        /**
         * Creates a JWS input from a JWS header and a payload.
         *
         * @param header  The JWS header.
         * @param payload The payload.
         */
        ComposedJWSInput(final JWSHeader header, final Payload payload) {

                this.header = Objects.requireNonNull(header).toBase64URL();
                this.payload = Objects.requireNonNull(payload);
                this.base64URLEncodePayload = header.isBase64URLEncodePayload();
        }


        @Override
        public String toString() {

                if (base64URLEncodePayload) {
                        return header.toString() + '.' + payload.toBase64URL().toString();
                } else {
                        return header.toString() + '.' + payload.toString();
                }
        }


        @Override
        public byte[] toByteArray() {

                final byte[] headerBytes = encodeUTF8(header);
                final byte[] payloadBytes = getEncodedPayloadByteArray();
                final int length = headerBytes.length + 1 + payloadBytes.length;
                return ByteBuffer.allocate(length).put(headerBytes).put((byte) '.').put(payloadBytes).array();
        }


        @Override
        public void apply(final Signature signature) throws SignatureException {

                signature.update(encodeUTF8(header));
                signature.update((byte) '.');
                signature.update(getEncodedPayloadByteArray());
        }


        @Override
        public void apply(final Mac mac) {

                mac.update(encodeUTF8(header));
                mac.update((byte) '.');
                mac.update(getEncodedPayloadByteArray());
        }


        private byte[] getEncodedPayloadByteArray() {

                return base64URLEncodePayload ? encodeUTF8(payload.toBase64URL()) : payload.toBytes();
        }


        private static byte[] encodeUTF8(final Base64URL url) {

                return url.toString().getBytes(StandardCharset.UTF_8);
        }
}
