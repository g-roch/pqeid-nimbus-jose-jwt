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

package com.nimbusds.jwt.util;


import java.util.Date;


/**
 * Date utilities.
 */
public class DateUtils {
	
	
	/**
	 * Returns the current {@link Date}, with the milliseconds removed.
	 *
	 * @return The current {@link Date}, with seconds precision.
	 */
	public static Date nowWithSecondsPrecision() {
		
		return fromSecondsSinceEpoch(toSecondsSinceEpoch(new Date()));
	}


	/**
	 * Converts the specified {@link Date} to seconds since the Unix epoch.
	 *
	 * @param date The {@link Date}. Must not be {@code null}.
	 *
	 * @return The seconds since the Unix epoch.
	 */
	public static long toSecondsSinceEpoch(final Date date) {

		return date.getTime() / 1000L;
	}


	/**
	 * Converts the specified seconds since the Unix epoch to a
	 * {@link Date}.
	 *
	 * @param time The seconds since the Unix epoch. Must not be negative.
	 *
	 * @return The {@link Date}.
	 */
	public static Date fromSecondsSinceEpoch(final long time) {

		return new Date(time * 1000L);
	}


	/**
	 * Check if the specified {@link Date} is after the specified
	 * reference, given the maximum accepted negative clock skew.
	 *
	 * <p>Formula:
	 *
	 * <pre>
	 * return date + clock_skew &gt; reference
	 * </pre>
	 *
	 * Example: Ensure a JWT expiration (exp) timestamp is after the
	 * current time, with a minute of acceptable clock skew.
	 *
	 * <pre>
	 * boolean valid = DateUtils.isAfter(exp, new Date(), 60);
	 * </pre>
	 *
	 * @param date                The {@link Date} to check. Must not be
	 *                            {@code null}.
	 * @param reference           The reference {@link Date} (e.g. the
	 *                            current time). Must not be {@code null}.
	 * @param maxClockSkewSeconds The maximum acceptable negative clock
	 *                            skew of the date value to check, in
	 *                            seconds.
	 *
	 * @return {@code true} if the {@link Date} is before the reference,
	 *         plus the maximum accepted clock skew, else {@code false}.
	 */
	public static boolean isAfter(final Date date,
				      final Date reference,
				      final long maxClockSkewSeconds) {

		return new Date(date.getTime() + maxClockSkewSeconds*1000L).after(reference);
	}


	/**
	 * Checks if the specified {@link Date} is before the specified
	 * reference, given the maximum accepted positive clock skew.
	 *
	 * <p>Formula:
	 *
	 * <pre>
	 * return date - clock_skew &lt; reference
	 * </pre>
	 *
	 * Example: Ensure a JWT issued-at (iat) timestamp is before the
	 * current time, with a minute of acceptable clock skew.
	 *
	 * <pre>
	 * boolean valid = DateUtils.isBefore(iat, new Date(), 60);
	 * </pre>
	 *
	 * @param date                The {@link Date} to check. Must not be
	 *                            {@code null}.
	 * @param reference           The reference {@link Date} (e.g. the
	 *                            current time). Must not be {@code null}.
	 * @param maxClockSkewSeconds The maximum acceptable clock skew of the
	 *                            date value to check, in seconds.
	 *
	 * @return {@code true} if the {@link Date} is before the reference,
	 *         minus the maximum accepted clock skew, else {@code false}.
	 */
	public static boolean isBefore(final Date date,
				       final Date reference,
				       final long maxClockSkewSeconds) {

		return new Date(date.getTime() - maxClockSkewSeconds*1000L).before(reference);
	}
	
	
	/**
	 * Checks if the specified {@link Date} is within the specified
	 * reference, give or take the maximum accepted clock skew.
	 *
	 * @param date                The {@link Date} to check. Must not be
	 *                            {@code null}.
	 * @param reference           The reference {@link Date} (e.g. the
	 *                            current time). Must not be {@code null}.
	 * @param maxClockSkewSeconds The maximum acceptable clock skew of the
	 *                            date value to check, in seconds.
	 *
	 * @return {@code true} if the {@link Date} is within the reference,
	 *         give or take the maximum accepted clock skew, else
	 *         {@code false}.
	 */
	public static boolean isWithin(final Date date,
				       final Date reference,
				       final long maxClockSkewSeconds) {
		
		long minTime = reference.getTime() - maxClockSkewSeconds*1000L;
		long maxTime = reference.getTime() + maxClockSkewSeconds*1000L;
		
		return date.getTime() > minTime && date.getTime() < maxTime;
	}


	/**
	 * Prevents instantiation.
	 */
	private DateUtils() { }
}
