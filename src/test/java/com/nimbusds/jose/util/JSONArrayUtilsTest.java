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

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;


public class JSONArrayUtilsTest {


        @Test
        public void parse_null() {

                try {
                        JSONArrayUtils.parse(null);
                        fail();
                } catch (ParseException e) {
                        assertEquals("The JSON array string must not be null", e.getMessage());
                }
        }


        @Test
        public void parse_emptyString() {

                try {
                        JSONArrayUtils.parse("");
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid JSON array", e.getMessage());
                }
        }


        @Test
        public void parse_blankString() {

                try {
                        JSONArrayUtils.parse(" ");
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid JSON array", e.getMessage());
                }
        }


        @Test
        public void parseOneItem() throws ParseException {

                assertEquals(Collections.singletonList(1L), JSONArrayUtils.parse("[1]"));
        }


        @Test
        public void parseTwoItems() throws ParseException {

                assertEquals(Arrays.asList("abc", 1L), JSONArrayUtils.parse("[\"abc\",1]"));
        }


        @Test
        public void parseTwoItems_trailingComma() {

                try {
                        JSONArrayUtils.parse("[\"abc\",1,]");
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid JSON array", e.getMessage());
                }
        }


        @Test
        public void parseTwoItems_unescapedString() {

                try {
                        JSONArrayUtils.parse("[abc,1]");
                        fail();
                } catch (ParseException e) {
                        assertEquals("Invalid JSON array", e.getMessage());
                }
        }


        @Test
        public void parseThreeItems() throws ParseException {

                assertEquals(Arrays.asList("abc", 1L, JSONObjectUtils.newJSONObject()), JSONArrayUtils.parse("[\"abc\",1,{}]"));
        }


        @Test
        public void toJSONString_null() {

                try {
                        JSONArrayUtils.toJSONString(null);
                        fail();
                } catch (NullPointerException e) {
                        assertNull(e.getMessage());
                }
        }


        @Test
        public void empty() {

                assertEquals("[]", JSONArrayUtils.toJSONString(Collections.emptyList()));
        }


        @Test
        public void toJSONString_oneNumberItem() {

                assertEquals("[1]", JSONArrayUtils.toJSONString(Collections.singletonList(1)));
        }


        @Test
        public void toJSONString_oneStringItem() {

                assertEquals("[\"abc\"]", JSONArrayUtils.toJSONString(Collections.singletonList("abc")));
        }


        @Test
        public void toJSONString_twoItem2() {

                assertEquals("[\"abc\",1]", JSONArrayUtils.toJSONString(Arrays.asList("abc", 1)));
        }
}