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

package com.nimbusds.jose.jwk;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;

public class KeyRevocationTest extends TestCase {

        public void testReasonConstants() {

                assertEquals("unspecified", KeyRevocation.Reason.UNSPECIFIED.getValue());
                assertEquals("compromised", KeyRevocation.Reason.COMPROMISED.getValue());
                assertEquals("superseded", KeyRevocation.Reason.SUPERSEDED.getValue());
        }


        public void testReasonLifeCycle() {

                String value = "investigated";
                KeyRevocation.Reason reason = new KeyRevocation.Reason(value);
                assertEquals(value, reason.getValue());
                assertEquals(value, reason.toString());

                assertEquals(reason, new KeyRevocation.Reason(value));
                assertEquals(reason.hashCode(), new KeyRevocation.Reason(value).hashCode());

                assertEquals(reason, KeyRevocation.Reason.parse(value));
        }

        public void testReasonParseConstant() {

                assertEquals(KeyRevocation.Reason.UNSPECIFIED, KeyRevocation.Reason.parse("unspecified"));
                assertEquals(KeyRevocation.Reason.COMPROMISED, KeyRevocation.Reason.parse("compromised"));
                assertEquals(KeyRevocation.Reason.SUPERSEDED, KeyRevocation.Reason.parse("superseded"));
        }


        public void testReason_inequality() {

                assertNotSame(
                        KeyRevocation.Reason.SUPERSEDED,
                        KeyRevocation.Reason.COMPROMISED
                );
        }


        public void testReasonConstructor_null() {

                try {
                        new KeyRevocation.Reason(null);
                        fail();
                } catch (NullPointerException e) {
                        assertNull(e.getMessage());
                }
        }


        public void testReasonParse_null() {

                try {
                        KeyRevocation.Reason.parse(null);
                        fail();
                } catch (NullPointerException e) {
                        assertNull(e.getMessage());
                }
        }


        public void testLifeCycle() throws ParseException {

                Date revokedAt = DateUtils.nowWithSecondsPrecision();
                KeyRevocation revocation = new KeyRevocation(revokedAt, null);
                assertEquals(revokedAt, revocation.getRevocationTime());
                assertNull(revocation.getReason());

                Map<String, Object> jsonObject = revocation.toJSONObject();
                assertEquals(DateUtils.toSecondsSinceEpoch(revokedAt), jsonObject.get("revoked_at"));
                assertEquals(1, jsonObject.size());

                KeyRevocation parsed = KeyRevocation.parse(jsonObject);
                assertEquals(revokedAt, revocation.getRevocationTime());
                assertNull(revocation.getReason());
                assertEquals(parsed, revocation);
                assertEquals(parsed.hashCode(), revocation.hashCode());
        }


        public void testLifeCycleWithReason() throws ParseException {

                Date revokedAt = DateUtils.nowWithSecondsPrecision();
                KeyRevocation.Reason reason = KeyRevocation.Reason.SUPERSEDED;
                KeyRevocation revocation = new KeyRevocation(revokedAt, reason);
                assertEquals(revokedAt, revocation.getRevocationTime());
                assertEquals(reason, revocation.getReason());

                Map<String, Object> jsonObject = revocation.toJSONObject();
                assertEquals(DateUtils.toSecondsSinceEpoch(revokedAt), jsonObject.get("revoked_at"));
                assertEquals(reason.getValue(), jsonObject.get("reason"));
                assertEquals(2, jsonObject.size());

                KeyRevocation parsed = KeyRevocation.parse(jsonObject);
                assertEquals(revokedAt, revocation.getRevocationTime());
                assertEquals(reason, revocation.getReason());
                assertEquals(parsed, revocation);
                assertEquals(parsed.hashCode(), revocation.hashCode());
        }


        public void testInequality() {

                assertNotSame(
                        new KeyRevocation(DateUtils.nowWithSecondsPrecision(), null),
                        new KeyRevocation(DateUtils.fromSecondsSinceEpoch(0L), null)
                );

                assertNotSame(
                        new KeyRevocation(DateUtils.fromSecondsSinceEpoch(0L), KeyRevocation.Reason.SUPERSEDED),
                        new KeyRevocation(DateUtils.fromSecondsSinceEpoch(0L), KeyRevocation.Reason.UNSPECIFIED)
                );

                assertNotSame(
                        new KeyRevocation(DateUtils.fromSecondsSinceEpoch(0L), null),
                        new KeyRevocation(DateUtils.fromSecondsSinceEpoch(0L), KeyRevocation.Reason.UNSPECIFIED)
                );

                assertNotSame(
                        new KeyRevocation(DateUtils.nowWithSecondsPrecision(), null),
                        "xxx"
                );
        }

        public void testConstructor_nullRevokedAt() {

                try {
                        new KeyRevocation(null, null);
                        fail();
                } catch (NullPointerException e) {
                        assertNull(e.getMessage());
                }
        }


        public void testParse_missingRevokedAt() {

                try {
                        KeyRevocation.parse(JSONObjectUtils.newJSONObject());
                        fail();
                } catch (ParseException e) {
                        assertEquals("JSON object member revoked_at is missing or null", e.getMessage());
                }
        }


        public void testParse_null() throws ParseException {
                try {
                        KeyRevocation.parse(null);
                        fail();
                } catch (NullPointerException e) {
                        assertEquals("Cannot invoke \"java.util.Map.get(Object)\" because \"o\" is null", e.getMessage());
                }
        }
}
