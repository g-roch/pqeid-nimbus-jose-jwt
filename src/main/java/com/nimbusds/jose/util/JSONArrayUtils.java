/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2024, Connect2id Ltd.
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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.Strictness;
import com.google.gson.ToNumberPolicy;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;


/**
 * JSON array helper methods.
 *
 * @author Toma Velev
 * @author Vladimir Dzhuvinov
 * @version 2024-11-14
 */
public class JSONArrayUtils {


	/**
	 * The GSon instance for serialisation and parsing.
	 */
	private static final Gson GSON = new GsonBuilder()
		.setStrictness(Strictness.STRICT)
		.serializeNulls()
		.setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE)
		.disableHtmlEscaping()
		.create();


	/**
	 * Parses a JSON array.
	 *
	 * <p>Specific JSON to Java entity mapping (as per JSON Smart):
	 *
	 * <ul>
	 *     <li>JSON true|false map to {@code java.lang.Boolean}.
	 *     <li>JSON numbers map to {@code java.lang.Number}.
	 *         <ul>
	 *             <li>JSON integer numbers map to {@code long}.
	 *             <li>JSON fraction numbers map to {@code double}.
	 *         </ul>
	 *     <li>JSON strings map to {@code java.lang.String}.
	 *     <li>JSON arrays map to {@code java.util.List<Object>}.
	 *     <li>JSON objects map to {@code java.util.Map<String,Object>}.
	 * </ul>
	 *
	 * @param s The JSON array string to parse. Must not be {@code null}.
	 *
	 * @return The JSON object.
	 *
	 * @throws ParseException If the string cannot be parsed to a valid JSON
	 *                        object.
	 */
	public static List<Object> parse(final String s)
		throws ParseException {

		if (s == null) {
			throw new ParseException("The JSON array string must not be null", 0);
		}

		if (s.trim().isEmpty()) {
			throw new ParseException("Invalid JSON array", 0);
		}

		Type listType = TypeToken.getParameterized(List.class, Object.class).getType();

		try {
			return GSON.fromJson(s, listType);
		} catch (Exception e) {
			throw new ParseException("Invalid JSON array", 0);
		} catch (StackOverflowError e) {
			throw new ParseException("Excessive JSON object and / or array nesting", 0);
		}
	}


	/**
	 * Serialises the specified list to a JSON array using the entity
	 * mapping specified in {@link #parse(String)}.
	 *
	 * @param jsonArray The JSON array. Must not be {@code null}.
	 *
	 * @return The JSON array as string.
	 */
	public static String toJSONString(final List<?> jsonArray) {
		return GSON.toJson(Objects.requireNonNull(jsonArray));
	}


	/**
	 * Creates a new JSON array.
	 *
	 * @return The new empty JSON array.
	 */
	public static List<Object> newJSONArray() {
		return new ArrayList<>();
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private JSONArrayUtils() { }
}
