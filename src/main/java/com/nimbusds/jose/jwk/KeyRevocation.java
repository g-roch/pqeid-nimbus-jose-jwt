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
import net.jcip.annotations.Immutable;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.Objects;


/**
 * Key revocation.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-04-27
 */
@Immutable
public final class KeyRevocation implements Serializable {


        /**
         * Key revocation reason.
         */
        public static class Reason {


                /**
                 * General or unspecified reason for the key status change.
                 */
                public static final Reason UNSPECIFIED = new Reason("unspecified");


                /**
                 * The private key is believed to have been compromised.
                 */
                public static final Reason COMPROMISED = new Reason("compromised");


                /**
                 * The key is no longer active.
                 */
                public static final Reason SUPERSEDED = new Reason("superseded");


                /**
                 * The reason value.
                 */
                private final String value;


                /**
                 * Creates a new reason with the specified value.
                 *
                 * @param value The reason value. Must not be {@code null}
                 */
                public Reason(final String value) {
                        this.value = Objects.requireNonNull(value);
                }


                /**
                 * Returns the reason value.
                 *
                 * @return The reason value.
                 */
                public String getValue() {
                        return value;
                }


                @Override
                public String toString() {
                        return getValue();
                }

                @Override
                public boolean equals(Object o) {
                        if (this == o) return true;
                        if (!(o instanceof Reason)) return false;
                        Reason reason = (Reason) o;
                        return Objects.equals(getValue(), reason.getValue());
                }

                @Override
                public int hashCode() {
                        return Objects.hashCode(getValue());
                }


                /**
                 * Parses a reason from the specified string.
                 *
                 * @param s The string. Must not be {@code null}.
                 *
                 * @return The reason.
                 */
                public static Reason parse(final String s) {
                        if (Reason.UNSPECIFIED.getValue().equals(s)) {
                                return Reason.UNSPECIFIED;
                        } else if (Reason.COMPROMISED.getValue().equals(s)) {
                                return Reason.COMPROMISED;
                        } else if (Reason.SUPERSEDED.getValue().equals(s)) {
                                return Reason.SUPERSEDED;
                        } else {
                                return new Reason(s);
                        }
                }
        }


        /**
         * The revocation time.
         */
        private final Date revokedAt;


        /**
         * The reason.
         */
        private final Reason reason;


        /**
         * Creates a new key revocation.
         *
         * @param revokedAt The revocation time.
         * @param reason    The reason.
         */
        public KeyRevocation(final Date revokedAt, final Reason reason) {
                this.revokedAt = Objects.requireNonNull(revokedAt);
                this.reason = reason;
        }


        /**
         * Returns the revocation time ({@code revoked_at}) parameter.
         *
         * @return The revocation time.
         */
        public Date getRevocationTime() {
                return revokedAt;
        }


        /**
         * Returns the reason ({@code reason}) parameter.
         *
         * @return The reason.
         */
        public Reason getReason() {
                return reason;
        }


        @Override
        public boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof KeyRevocation)) return false;
                KeyRevocation that = (KeyRevocation) o;
                return Objects.equals(revokedAt, that.revokedAt) && Objects.equals(getReason(), that.getReason());
        }


        @Override
        public int hashCode() {
                return Objects.hash(revokedAt, getReason());
        }


        /**
         * Returns a JSON object representation of this key revocation.
         *
         * @return The JSON object representation.
         */
        public Map<String, Object> toJSONObject() {
                Map<String, Object> o = JSONObjectUtils.newJSONObject();
                o.put("revoked_at", DateUtils.toSecondsSinceEpoch(getRevocationTime()));
                if (getReason() != null) {
                        o.put("reason", getReason().getValue());
                }
                return o;
        }


        /**
         * Parses a key revocation from the specified JSON object.
         *
         * @param jsonObject The JSON object. Must not be {@code null}.
         *
         * @return The key revocation.
         *
         * @throws ParseException If parsing failed.
         */
        public static KeyRevocation parse(final Map<String, Object> jsonObject)
                throws ParseException {
                Date revokedAt = DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(jsonObject, "revoked_at"));
                Reason reason = null;
                if (jsonObject.get("reason") != null) {
                        reason = Reason.parse(JSONObjectUtils.getString(jsonObject, "reason"));
                }
                return new KeyRevocation(revokedAt, reason);
        }
}
