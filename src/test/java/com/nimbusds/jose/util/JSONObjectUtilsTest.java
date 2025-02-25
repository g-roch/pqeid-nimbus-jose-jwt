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

package com.nimbusds.jose.util;


import com.google.gson.stream.JsonReader;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jwt.util.DateUtils;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.text.ParseException;
import java.util.*;

import static org.junit.Assert.*;


/**
 * Tests the JSON object utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2025-02-25
 */
public class JSONObjectUtilsTest {


        @Test
        public void testParseEmpty() throws ParseException {
		
		assertTrue(JSONObjectUtils.parse("{}").isEmpty());
	}


        @Test
        public void testParseFromNullString() {

		try {
			JSONObjectUtils.parse(null);
			fail();
		} catch (ParseException e) {
			assertEquals("The JSON object string must not be null", e.getMessage());
		}
	}


        @Test
        public void testParseFromEmptyString() {
		
		try {
			JSONObjectUtils.parse("");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseFromStringEntity() {
		
		try {
			JSONObjectUtils.parse("abc");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseTrailingWhiteSpace()
		throws Exception {

		assertEquals(0, JSONObjectUtils.parse("{} ").size());
		assertEquals(0, JSONObjectUtils.parse("{}\n").size());
		assertEquals(0, JSONObjectUtils.parse("{}\r\n").size());
	}


        @Test
        public void testParseObjectTrailingNonWhiteSpaceChar() {
		
		try {
			JSONObjectUtils.parse("{}a");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseObjectDuplicateMember() {
		
		try {
			JSONObjectUtils.parse("{\"iat\":1661335547,\"iat\":1661335547}");
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}
	
	
	// https://github.com/netplex/json-smart-v1/issues/7
	// 2021-04-06: JSON Smart 1.3.2 fixes CVE
	// 2022-08-16: Test rewritten for GSon
	// 2024-11-14: With strict GSon parsing we get an exception now
        @Test
        public void testParse_ignoreNumberFormatException() throws ParseException {
		
		String json = "{\"key\":2e+}";
		
		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
//		Map<String, Object> jsonObject = JSONObjectUtils.parse(json);
//
//		assertEquals("2e+", jsonObject.get("key"));
//		assertEquals(1, jsonObject.size());
	}
	
	
	// Originally a JSON Smart test, doesn't apply to GSon
        @Test
        public void testParse_catchStackOverflowError() {
	
		StringBuilder sb = new StringBuilder("{\"a\":");
		for (int i = 0; i < 6000; i++) {
			sb.append("[");
		}
		
		try {
			JSONObjectUtils.parse(sb.toString());
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParse_withSizeLimit() {
		
		int sizeLimit = 100;
		
		StringBuilder s = new StringBuilder();
		for (int i=0; i < 101; i++) {
			s.append("a");
		}
		assertEquals(101, s.toString().length());
		
		try {
			JSONObjectUtils.parse(s.toString(), sizeLimit);
			fail();
		} catch (ParseException e) {
			assertEquals("The parsed string is longer than the max accepted size of 100 characters", e.getMessage());
		}
	}


        @Test
        public void testParse_noSizeLimit() throws ParseException {
		
		Map<String,Object> map = new HashMap<>();
		
		StringBuilder s = new StringBuilder();
		for (int i=0; i < 101; i++) {
			s.append("a");
		}
		
		String value = s.toString();
		
		assertEquals(101, value.length());
		map.put("key", value);
		
		Map<String,Object> out = JSONObjectUtils.parse(JSONObjectUtils.toJSONString(map), -1);
		assertEquals(map, out);
		
		out = JSONObjectUtils.parse(JSONObjectUtils.toJSONString(map));
		assertEquals(map, out);
	}


        @Test
        public void testParse_intMember() throws ParseException {
		
		String json = "{\"auth_time\":1518022800}";
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse(json);
		
		assertEquals(1518022800L, jsonObject.get("auth_time"));
	}


        @Test
        public void testParse_floatMember() throws ParseException {
		
		String json = "{\"auth_time\":1.660730988E9}";
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse(json);
		
		assertEquals(1.660730988E9, jsonObject.get("auth_time"));
	}


        @Test
        public void testSerialize_intMember() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("auth_time", 1518022800);
		assertEquals("{\"auth_time\":1518022800}", JSONObjectUtils.toJSONString(jsonObject));
	}


        @Test
        public void testSerialize_longMember() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("auth_time", 1518022800L);
		assertEquals("{\"auth_time\":1518022800}", JSONObjectUtils.toJSONString(jsonObject));
	}


        @Test
        public void testSerialize_doubleMember() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("auth_time", 1.660730988E9);
		assertEquals("{\"auth_time\":1.660730988E9}", JSONObjectUtils.toJSONString(jsonObject));
	}


        @Test
        public void testGetBoolean_true()
		throws ParseException {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", true);
		assertTrue(JSONObjectUtils.getBoolean(jsonObject, "key"));
		
		// Parsed JSON object
		assertTrue(JSONObjectUtils.getBoolean(JSONObjectUtils.parse("{\"key\":true}"), "key"));
	}


        @Test
        public void testGetBoolean_false()
		throws ParseException {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", false);
		assertFalse(JSONObjectUtils.getBoolean(jsonObject, "key"));
		
		// Parsed JSON object
		assertFalse(JSONObjectUtils.getBoolean(JSONObjectUtils.parse("{\"key\":false}"), "key"));
	}


        @Test
        public void testGetBoolean_null() {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getBoolean(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getBoolean(JSONObjectUtils.parse("{\"key\":null}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetBoolean_missing() {
		
		// Map
		try {
			JSONObjectUtils.getBoolean(JSONObjectUtils.newJSONObject(), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getBoolean(JSONObjectUtils.parse("{}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetInt_null() {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getInt(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getInt(JSONObjectUtils.parse("{\"key\":null}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetInt_missing() {
		
		// Map
		try {
			JSONObjectUtils.getInt(JSONObjectUtils.newJSONObject(), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getInt(JSONObjectUtils.parse("{}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetInt_notNumber() {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", "abc");
		
		try {
			JSONObjectUtils.getInt(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member key", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getInt(JSONObjectUtils.parse("{\"key\":\"abc\"}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member key", e.getMessage());
		}
	}


        @Test
        public void testGetLong_null() {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getLong(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getLong(JSONObjectUtils.parse("{\"key\":null}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetLong_missing() {
		
		// Map
		try {
			JSONObjectUtils.getLong(JSONObjectUtils.newJSONObject(), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getLong(JSONObjectUtils.parse("{}"), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetFloat_null() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getFloat(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetFloat_missing() {
		
		try {
			JSONObjectUtils.getFloat(JSONObjectUtils.newJSONObject(), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetDouble_null() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		
		try {
			JSONObjectUtils.getDouble(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetDouble_missing() {
		
		try {
			JSONObjectUtils.getDouble(JSONObjectUtils.newJSONObject(), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is missing or null", e.getMessage());
		}
	}


        @Test
        public void testGetIntegerNumberAs_int_long_float_double() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse("{\"key\":10}");
		assertEquals(10, JSONObjectUtils.getInt(jsonObject, "key"));
		assertEquals(10L, JSONObjectUtils.getLong(jsonObject, "key"));
		assertEquals(10.0F, JSONObjectUtils.getFloat(jsonObject, "key"), 0.0);
		assertEquals(10.0D, JSONObjectUtils.getDouble(jsonObject, "key"), 0.0);
	}


        @Test
        public void testGetDecimalNumberAs_int_long_float_double() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse("{\"key\":3.14}");
		assertEquals(3, JSONObjectUtils.getInt(jsonObject, "key"));
		assertEquals(3L, JSONObjectUtils.getLong(jsonObject, "key"));
		assertEquals(3.14F, JSONObjectUtils.getFloat(jsonObject, "key"), 0.0);
		assertEquals(3.14D, JSONObjectUtils.getDouble(jsonObject, "key"), 0.0);
	}


        @Test
        public void testGetString() throws ParseException {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", "value");
		assertEquals("value", JSONObjectUtils.getString(jsonObject, "key"));
		
		// Parsed JSON object
		jsonObject = JSONObjectUtils.parse("{\"key\":\"value\"}");
		assertEquals("value", JSONObjectUtils.getString(jsonObject, "key"));
	}


        @Test
        public void testGetString_null() throws ParseException {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getString(jsonObject, "key"));
		
		// Parsed JSON object
		jsonObject = JSONObjectUtils.parse("{\"key\":null}");
		assertNull(JSONObjectUtils.getString(jsonObject, "key"));
	}


        @Test
        public void testGetString_missing() throws ParseException {
		
		// Map
		assertNull(JSONObjectUtils.getString(JSONObjectUtils.newJSONObject(), "key"));
		
		// Parsed JSON object
		assertNull(JSONObjectUtils.getString(JSONObjectUtils.parse("{}"), "key"));
	}


        @Test
        public void testGetURI() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", "https://c2id.net");
		assertEquals(URI.create("https://c2id.net"), JSONObjectUtils.getURI(jsonObject, "key"));
	}


        @Test
        public void testGetURI_illegal() {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", "a%b%c");
		try {
			JSONObjectUtils.getURI(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("Malformed escape pair at index 1: a%b%c", e.getMessage());
		}
	}


        @Test
        public void testGetURI_null() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getURI(jsonObject, "key"));
	}


        @Test
        public void testGetURI_missing() throws ParseException {
		
		assertNull(JSONObjectUtils.getURI(JSONObjectUtils.newJSONObject(), "key"));
	}


        @Test
        public void testGetJSONArray_null() throws ParseException {
		
		// Map
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getJSONArray(jsonObject, "key"));
		
		// Parsed JSON object
		assertNull(JSONObjectUtils.getJSONArray(JSONObjectUtils.parse("{\"key\":null}"), "key"));
	}


        @Test
        public void testGetJSONArray_missing() throws ParseException {
		
		// Map
		assertNull(JSONObjectUtils.getJSONArray(JSONObjectUtils.newJSONObject(), "key"));
		
		// Parsed JSON object
		assertNull(JSONObjectUtils.getJSONArray(JSONObjectUtils.parse("{}"), "key"));
	}


        @Test
        public void testGetStringArray() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
		Assert.assertArrayEquals(new String[]{"apple", "pear"}, JSONObjectUtils.getStringArray(jsonObject, "key"));
	}


        @Test
        public void testGetStringArray_otherTypes() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse("{\"key\":[10,true]}");
		try {
			JSONObjectUtils.getStringArray(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is not an array of strings", e.getMessage());
		}
	}


        @Test
        public void testGetStringArray_null() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getStringArray(jsonObject, "key"));
	}


        @Test
        public void testGetStringArray_missing() throws ParseException {
		
		assertNull(JSONObjectUtils.getStringArray(JSONObjectUtils.newJSONObject(), "key"));
	}


        @Test
        public void testGetStringList() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.parse("{\"key\":[\"apple\",\"pear\"]}");
		assertEquals(Arrays.asList("apple", "pear"), JSONObjectUtils.getStringList(jsonObject, "key"));
	}


        @Test
        public void testGetStringList_null() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getStringList(jsonObject, "key"));
	}


        @Test
        public void testGetStringList_missing() throws ParseException {
		
		assertNull(JSONObjectUtils.getStringList(JSONObjectUtils.newJSONObject(), "key"));
	}


        @Test
        public void testGetJSONObjectArray() throws ParseException {
		
		Map<String, Object> o1 = JSONObjectUtils.newJSONObject();
		o1.put("o1-key-1", "o1-val-1");
		
		Map<String, Object> o2 = JSONObjectUtils.newJSONObject();
		o2.put("o2-key-1", "o2-val-1");
		
		List<Object> jsonArray = Arrays.asList(o1, (Object) o2);
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", jsonArray);
		
		Map<String, Object>[] array = JSONObjectUtils.getJSONObjectArray(jsonObject, "key");
		
		assertEquals("o1-val-1", array[0].get("o1-key-1"));
		assertEquals(1, array[0].size());
		
		assertEquals("o2-val-1", array[1].get("o2-key-1"));
		assertEquals(1, array[1].size());
		
		assertEquals(2, array.length);
	}


        @Test
        public void testGetJSONObjectArray_nullItems() throws ParseException {

		Map<String, Object> o1 = JSONObjectUtils.newJSONObject();
		o1.put("o1-key-1", "o1-val-1");

		Map<String, Object> o2 = JSONObjectUtils.newJSONObject();
		o2.put("o2-key-1", "o2-val-1");

		List<Object> jsonArray = Arrays.asList(o1, null, (Object) o2, null);

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", jsonArray);

		Map<String, Object>[] array = JSONObjectUtils.getJSONObjectArray(jsonObject, "key");
		assertEquals(o1, array[0]);
		assertNull(array[1]);
		assertEquals(o2, array[2]);
		assertNull(array[3]);
		assertEquals(4, array.length);
	}


        @Test
        public void testGetJSONObjectArray_parsedJSONObject() throws ParseException {
		
		Map<String, Object> o1 = JSONObjectUtils.newJSONObject();
		o1.put("o1-key-1", "o1-val-1");
		
		Map<String, Object> o2 = JSONObjectUtils.newJSONObject();
		o2.put("o2-key-1", "o2-val-1");
		
		List<Object> jsonArray = Arrays.asList(o1, (Object) o2);
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", jsonArray);
		
		String json = JSONObjectUtils.toJSONString(jsonObject);
		
		jsonObject = JSONObjectUtils.parse(json);
		
		Map<String, Object>[] array = JSONObjectUtils.getJSONObjectArray(jsonObject, "key");
		
		assertEquals("o1-val-1", array[0].get("o1-key-1"));
		assertEquals(1, array[0].size());
		
		assertEquals("o2-val-1", array[1].get("o2-key-1"));
		assertEquals(1, array[1].size());
		
		assertEquals(2, array.length);
	}


        @Test
        public void testGetJSONObjectArray_null() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		
		assertNull(JSONObjectUtils.getJSONObjectArray(jsonObject, "key"));
	}


        @Test
        public void testGetJSONObjectArray_none() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		
		assertNull(JSONObjectUtils.getJSONObjectArray(jsonObject, "key"));
	}


        @Test
        public void testGetJSONObjectArray_empty() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", JSONArrayUtils.newJSONArray());
		
		assertEquals(0, JSONObjectUtils.getJSONObjectArray(jsonObject, "key").length);
		
		assertEquals(0, JSONObjectUtils.getJSONObjectArray(JSONObjectUtils.parse("{\"key\":[]}"), "key").length);
	}


        @Test
        public void testGetJSONObjectArray_itemTypeNotJSONObject() {
		
		Map<String, Object> o1 = JSONObjectUtils.newJSONObject();
		o1.put("o1-key-1", "o1-val-1");
		
		List<Object> jsonArray = Arrays.asList(o1, "string-item");
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", jsonArray);
		
		try {
			JSONObjectUtils.getJSONObjectArray(jsonObject, "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is not an array of JSON objects", e.getMessage());
		}
		
		// Parsed JSON object
		try {
			JSONObjectUtils.getJSONObjectArray(JSONObjectUtils.parse(JSONObjectUtils.toJSONString(jsonObject)), "key");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member key is not an array of JSON objects", e.getMessage());
		}
	}


        @Test
        public void testGetJSONObjectArray_itemNull() throws ParseException {
		
		Map<String, Object> o1 = JSONObjectUtils.newJSONObject();
		o1.put("o1-key-1", "o1-val-1");
		
		List<Object> jsonArray = Arrays.asList((Object) o1, null);
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", jsonArray);
		
		Map<String, Object>[] array = JSONObjectUtils.getJSONObjectArray(jsonObject, "key");
		
		assertEquals("o1-val-1", array[0].get("o1-key-1"));
		assertEquals(1, array[0].size());
		
		assertNull(array[1]);
		
		assertEquals(2, array.length);
	}


        @Test
        public void testGetJSONObjectArray_itemNull_parsedJSONObject() throws ParseException {
		
		Map<String, Object> o1 = JSONObjectUtils.newJSONObject();
		o1.put("o1-key-1", "o1-val-1");
		
		List<Object> jsonArray = Arrays.asList((Object) o1, null);
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", jsonArray);
		
		String json = JSONObjectUtils.toJSONString(jsonObject);
		
		jsonObject = JSONObjectUtils.parse(json);
		
		Map<String, Object>[] array = JSONObjectUtils.getJSONObjectArray(jsonObject, "key");
		
		assertEquals("o1-val-1", array[0].get("o1-key-1"));
		assertEquals(1, array[0].size());
		
		assertNull(array[1]);
		
		assertEquals(2, array.length);
	}


        @Test
        public void testGetJSONObject() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		
		Map<String, Object> value = JSONObjectUtils.newJSONObject();
		value.put("one", 1);
		value.put("two", "2");
		value.put("three", null);
		jsonObject.put("key", value);
		
		assertEquals(value, JSONObjectUtils.getJSONObject(jsonObject, "key"));
		
		assertEquals(1, JSONObjectUtils.getJSONObject(jsonObject, "key").get("one"));
		assertEquals("2", JSONObjectUtils.getJSONObject(jsonObject, "key").get("two"));
		assertNull(JSONObjectUtils.getJSONObject(jsonObject, "key").get("three"));
	}


        @Test
        public void testGetJSONObject_parsedJSONObject() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		
		Map<String, Object> value = JSONObjectUtils.newJSONObject();
		value.put("one", 1);
		value.put("two", "2");
		value.put("three", null);
		jsonObject.put("key", value);
		
		String json = JSONObjectUtils.toJSONString(jsonObject);
		
		jsonObject = JSONObjectUtils.parse(json);
		
		// GSon parses one:1 as one:1.0!
		Assert.assertNotSame(value, JSONObjectUtils.getJSONObject(jsonObject, "key"));
		
		value = JSONObjectUtils.getJSONObject(jsonObject, "key");
		
		assertEquals(1, JSONObjectUtils.getInt(value, "one"));
		assertEquals("2", JSONObjectUtils.getString(value, "two"));
		assertTrue(value.containsKey("three"));
		assertNull(value.get("three"));
	}


        @Test
        public void testGetJSONObject_valueNotMapOfStringObjectPairs() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		
		Map<Integer, Object> value = new HashMap<>();
		value.put(1, 2);
		value.put(3, 4);
		jsonObject.put("AAA", value);
		
		try {
			JSONObjectUtils.getJSONObject(jsonObject, "AAA");
			fail();
		} catch (ParseException e) {
			assertEquals("JSON object member AAA not a JSON object", e.getMessage());
		}
	}


        @Test
        public void testGetJSONObject_null() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", null);
		assertNull(JSONObjectUtils.getJSONObject(jsonObject, "key"));
		
		assertNull(JSONObjectUtils.getJSONObject(JSONObjectUtils.parse("{\"key\":null}"), "key"));
	}


        @Test
        public void testGetJSONObject_missing() throws ParseException {
		
		assertNull(JSONObjectUtils.getJSONObject(JSONObjectUtils.newJSONObject(), "key"));
		
		assertNull(JSONObjectUtils.getJSONObject(JSONObjectUtils.parse("{}"), "key"));
	}


        @Test
        public void testGetBase64URL() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT, "abc");
		Base64URL base64URL = JSONObjectUtils.getBase64URL(jsonObject, HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT);
		assertEquals("abc", base64URL.toString());
	}


        @Test
        public void testGetBase64URL_null() throws ParseException {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT, null);
		assertNull(JSONObjectUtils.getBase64URL(jsonObject, HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
	}


        @Test
        public void testGetBase64URL_missing() throws ParseException {
		
		assertNull(JSONObjectUtils.getBase64URL(JSONObjectUtils.newJSONObject(), HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT));
	}


        @Test
        public void testToJSONString_unixTimestamp() throws ParseException {
		
		Date now = DateUtils.nowWithSecondsPrecision();
		
		long ts = DateUtils.toSecondsSinceEpoch(now);
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("now", ts);
		
		String json = JSONObjectUtils.toJSONString(jsonObject);
		
		assertEquals("{\"now\":" + ts + "}", json);
		
		jsonObject = JSONObjectUtils.parse(json);
		assertEquals(ts, JSONObjectUtils.getLong(jsonObject, "now"));
	}


        @Test
        public void testGetEpochSecondAsDate() throws ParseException {

		Date now = DateUtils.nowWithSecondsPrecision();

		long ts = DateUtils.toSecondsSinceEpoch(now);

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("now", ts);

		String json = JSONObjectUtils.toJSONString(jsonObject);

		jsonObject = JSONObjectUtils.parse(json);
		assertEquals(now, JSONObjectUtils.getEpochSecondAsDate(jsonObject, "now"));
		assertEquals(ts, JSONObjectUtils.getLong(jsonObject, "now"));
	}


        @Test
        public void testGetEpochSecondAsDate_null() throws ParseException {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("now", null);

		String json = JSONObjectUtils.toJSONString(jsonObject);

		jsonObject = JSONObjectUtils.parse(json);
		assertNull(JSONObjectUtils.getEpochSecondAsDate(jsonObject, "now"));
	}


        @Test
        public void testGetEpochSecondAsDate_missing() throws ParseException {

		assertNull(JSONObjectUtils.getEpochSecondAsDate(JSONObjectUtils.newJSONObject(), "now"));
	}


        @Test
        public void testGetEpochSecondAsDate_illegal() throws ParseException {

		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("now", "xxx");

		String json = JSONObjectUtils.toJSONString(jsonObject);

		jsonObject = JSONObjectUtils.parse(json);
		try {
			JSONObjectUtils.getEpochSecondAsDate(jsonObject, "now");
			fail();
		} catch (ParseException e) {
			assertEquals("Unexpected type of JSON object member now", e.getMessage());
		}
	}


        @Test
        public void testSerialize_escape() {
	
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("key", "\"\\<>&'=");
		assertEquals("{\"key\":\"\\\"\\\\<>&'=\"}", JSONObjectUtils.toJSONString(jsonObject));
	}


        @Test
        public void testBase64Value() throws ParseException {
		
		Base64 base64 = new Base64("xHPBC7VaQxq6AAvrBQN4YQ==");
		Map<String, Object> o = new HashMap<>();
		o.put("b64", base64.toString());
		
		String json = JSONObjectUtils.toJSONString(o);
		o = JSONObjectUtils.parse(json);
		
		assertEquals(base64.toString(), o.get("b64"));
	}


        @Test
        public void testToJSONString_null() {

		try {
			JSONObjectUtils.toJSONString(null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}


        @Test
        public void testParseNonStrictJSONObject_unescapedKey() {

		String json = "{key1:\"value1\"}";

		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseNonStrictJSONObject_unescapedValue() {

		String json = "{\"key1\":value1}";

		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseNonStrictJSONObject_unescapedKeyAndValue() {

		String json = "{key1:value1}";

		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseNonStrictJSONObject_trailingComma() {

		String json = "{\"key1\":\"value1\",}";

		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


        @Test
        public void testParseNonStrictJSONObject_jwkSet() {

		String json = "{keys: [{kty: RSA, e: AQAB, kid: eee9f17a3b598fd86417a980b591fbe6, alg: RS384, n: wJq2RHIA-7RT6q4go7wjcbHdW7ck7Kz22A8wf-kN7Wi5CWvhFG2_Y7nQp1lDpb2IKMQr }]}";

		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


	public static Map<String, Object> createJSONObjectWithNesting(int depth) {
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		Map<String, Object> ref = jsonObject;
		for (int i=0; i < depth; i++) {
			Map<String, Object> nested = JSONObjectUtils.newJSONObject();
			ref.put("a", nested);
			ref = nested;
		}
		return jsonObject;
	}


	@Test
	public void testParseWithMaxJSONObjectNesting()
		throws ParseException {

		JsonReader jsonReader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(new byte[]{})));
		int nestingLimit = jsonReader.getNestingLimit();
		assertEquals(255, nestingLimit);

		Map<String, Object> jsonObject = createJSONObjectWithNesting(nestingLimit - 1);
		String json = JSONObjectUtils.toJSONString(jsonObject);
		assertEquals(jsonObject, JSONObjectUtils.parse(json));
	}


	@Test
	public void testParseWithExcessiveJSONObjectNesting() {

		JsonReader jsonReader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(new byte[]{})));
		int nestingLimit = jsonReader.getNestingLimit();
		assertEquals(255, nestingLimit);

		Map<String, Object> jsonObject = createJSONObjectWithNesting(nestingLimit);
		String json = JSONObjectUtils.toJSONString(jsonObject);

		try {
			JSONObjectUtils.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}
}
