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
package com.nimbusds.jose;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import java.nio.ByteBuffer;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Objects;
import javax.crypto.Mac;

/**
 * Implements a signing input from a {@link JWSHeader} and {@link Payload} that
 * leverages {@link SigningInput#apply(Signature)} to feed the signature input
 * into a {@link Signature}. For signing and verification algorithms that
 * operate on a JCA {@link Signature} type this may avoid materializing the
 * signing input into a temporary byte array.
 *
 * <p>This is especially meaningful for {@link Payload} instances that have been
 * created using {@link Payload#Payload(byte[])} together with the "b64" JWS
 * header (see {@link JWSHeader#isBase64URLEncodePayload()}), as the payload's
 * byte array won't have to be copied into an intermediate byte array
 *
 * @version 2025-03-01
 * @since 11.0
 */
final class ComposedSigningInput implements SigningInput {


  private final Base64URL header;
  private final Payload payload;
  private final boolean base64URLEncodePayload;

  /**
   * Creates a signing input from a JWS header and the payload.
   *
   * @param header The JWS header to use as signing input.
   * @param payload The payload to use as signing input.
   */
  ComposedSigningInput(final JWSHeader header, final Payload payload) {

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
  public void apply(Mac mac) {

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
