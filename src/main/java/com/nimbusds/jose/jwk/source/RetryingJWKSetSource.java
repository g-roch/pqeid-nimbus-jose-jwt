/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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

package com.nimbusds.jose.jwk.source;

import java.util.Objects;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.events.EventListener;


/**
 * {@linkplain JWKSetSource} with with retry capability to work around
 * transient network issues. In cases when the underlying source throws a
 * {@linkplain JWKSetUnavailableException} the retrieval is tried once again.
 *
 * @author Thomas Rørvik Skjølberg
 * @version 2022-11-22
 */
@ThreadSafe
public class RetryingJWKSetSource<C extends SecurityContext> extends JWKSetSourceWrapper<C> {
	
	
	/**
	 * Retrial event.
	 */
	public static class RetrialEvent<C extends SecurityContext> extends AbstractJWKSetSourceEvent<RetryingJWKSetSource<C>, C> {
		
		private final Exception exception;
		
		private RetrialEvent(final RetryingJWKSetSource<C> source,
				     final Exception exception,
				     final C securityContext) {
			super(source, securityContext);
			Objects.requireNonNull(exception);
			this.exception = exception;
		}
		
		
		/**
		 * Returns the exception that caused the retrial.
		 *
		 * @return The exception.
		 */
		public Exception getException() {
			return exception;
		}
	}
	
	
	private final EventListener<RetryingJWKSetSource<C>, C> eventListener;
	
	
	/**
	 * Creates a new JWK set source with support for retrial.
	 *
	 * @param source        The JWK set source to decorate. Must not be
	 *                      {@code null}.
	 * @param eventListener The event listener, {@code null} if not
	 *                      specified.
	 */
	public RetryingJWKSetSource(final JWKSetSource<C> source,
				    final EventListener<RetryingJWKSetSource<C>, C> eventListener) {
		super(source);
		this.eventListener = eventListener;
	}

	
	@Override
	public JWKSet getJWKSet(final JWKSetCacheRefreshEvaluator refreshEvaluator, final long currentTime, final C context)
		throws KeySourceException {
		
		try {
			return getSource().getJWKSet(refreshEvaluator, currentTime, context);
			
		} catch (JWKSetUnavailableException e) {
			// assume transient network issue, retry once
			if (eventListener != null) {
				eventListener.notify(new RetrialEvent<>(this, e, context));
			}
			return getSource().getJWKSet(refreshEvaluator, currentTime, context);
		}
	}
}
