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
import net.jcip.annotations.ThreadSafe;

import java.text.ParseException;
import java.util.Objects;


/**
 * Unsecured (plain / {@code alg=none}) JOSE object with
 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.1">compact
 * serialisation</a>.
 *
 * <p>This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-04-20
 */
@ThreadSafe
public class PlainObject extends JOSEObject {


	private static final long serialVersionUID = 1L;


	/**
	 * The header.
	 */
	private final PlainHeader header;


	/**
	 * Creates a new unsecured JOSE object with a default {@link
	 * PlainHeader} and the specified payload.
	 *
	 * @param payload The payload. Must not be {@code null}.
	 */
	public PlainObject(final Payload payload) {

		setPayload(Objects.requireNonNull(payload));
		header = new PlainHeader();
	}


	/**
	 * Creates a new unsecured JOSE object with the specified header and
	 * payload.
	 *
	 * @param header  The unsecured header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	public PlainObject(final PlainHeader header, final Payload payload) {

		this.header = Objects.requireNonNull(header);
		setPayload(Objects.requireNonNull(payload));
	}


	/**
	 * Creates a new unsecured JOSE object with the specified
	 * Base64URL-encoded parts.
	 *
	 * @param firstPart  The first part, corresponding to the unsecured
	 *                   header. Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the payload. 
	 *                   Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public PlainObject(final Base64URL firstPart, final Base64URL secondPart)
		throws ParseException {

		try {
			header = PlainHeader.parse(Objects.requireNonNull(firstPart));

		} catch (ParseException e) {

			throw new ParseException("Invalid unsecured header: " + e.getMessage(), 0);
		}

		setPayload(new Payload(Objects.requireNonNull(secondPart)));

		setParsedParts(firstPart, secondPart, null);
	}


	@Override
	public PlainHeader getHeader() {

		return header;
	}


	/**
	 * Serialises this unsecured JOSE object to its compact format
	 * consisting of Base64URL-encoded parts delimited by period ('.') 
	 * characters.
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url].[]
	 * </pre>
	 *
	 * @return The serialised unsecured JOSE object.
	 */
	@Override
	public String serialize() {

		return header.toBase64URL().toString() + '.' + getPayload().toBase64URL().toString() + '.';
	}


	/**
	 * Parses an unsecured JOSE object from the specified string in compact
	 * format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The unsecured JOSE object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        unsecured JOSE object.
	 */
	public static PlainObject parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (! parts[2].toString().isEmpty()) {
			
			throw new ParseException("Unexpected third Base64URL part", 0);
		}

		return new PlainObject(parts[0], parts[1]);
	}
}
