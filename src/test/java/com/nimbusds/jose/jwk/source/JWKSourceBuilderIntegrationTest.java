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

package com.nimbusds.jose.jwk.source;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthReportListener;
import com.nimbusds.jose.util.health.HealthStatus;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;


public class JWKSourceBuilderIntegrationTest {
	
	private static final JWK EC_JWK_1;
	private static final JWK EC_JWK_2;
	
	static {
		try {
			EC_JWK_1 = new ECKeyGenerator(Curve.P_256)
				.keyID("1")
				.generate()
				.toPublicJWK();
			EC_JWK_2 = new ECKeyGenerator(Curve.P_256)
				.keyID("2")
				.generate()
				.toPublicJWK();
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}
	
	private static final JWKSet JWK_SET_1 = new JWKSet(EC_JWK_1);
	private static final JWKSet JWK_SET_1_2 = new JWKSet(Arrays.asList(EC_JWK_1, EC_JWK_2));
	private static final SecurityContext CONTEXT = new SimpleSecurityContext();
	private URL jwkSetURL;
	
	
	@Before
	public void setUp() throws MalformedURLException {
		
		initJadler();
		
		jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");
	}
	
	
	@After
	public void tearDown() {
		
		closeJadler();
	}
	
	
	@Test
	public void defaultsScenario() throws KeySourceException {
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");
		
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(jwkSetURL)
			.build();
		
		// Retrieve and cache
		List<JWK> jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);
		
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		closeJadler();
		
		// Return from cache
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);
		
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		// Unknown kid
		try {
			source.get(new JWKSelector(new JWKMatcher.Builder().keyID("no-such-kid").build()), null);
			fail();
		} catch (KeySourceException e) {
			assertTrue(e.getMessage().startsWith("Couldn't retrieve JWK set from URL: "));
		}
	}


	@Test
	public void httpTimeouts() throws KeySourceException {

		int httpConnectTimeout = 100;
		int httpReadTimeout = 250;

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");

		JWKSource<SecurityContext> source = JWKSourceBuilder.create(
				jwkSetURL,
				new DefaultResourceRetriever(httpConnectTimeout, httpReadTimeout))
			.build();

		// Retrieve and cache
		List<JWK> jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);

		assertEquals(Collections.singletonList(EC_JWK_1), jwks);

		closeJadler();

		// Return from cache
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);

		assertEquals(Collections.singletonList(EC_JWK_1), jwks);

		// Unknown kid
		try {
			source.get(new JWKSelector(new JWKMatcher.Builder().keyID("no-such-kid").build()), null);
			fail();
		} catch (KeySourceException e) {
			assertTrue(e.getMessage().startsWith("Couldn't retrieve JWK set from URL: "));
		}
	}


	@Test
	public void httpConnectTimeoutExceeded() {

		int httpConnectTimeout = 100;
		int httpReadTimeout = 250;

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withDelay(httpConnectTimeout * 10, TimeUnit.MILLISECONDS)
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");

		JWKSource<SecurityContext> source = JWKSourceBuilder.create(
				jwkSetURL,
				new DefaultResourceRetriever(httpConnectTimeout, httpReadTimeout))
			.build();

		try {
			source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);
			fail();
		} catch (KeySourceException e) {
			assertEquals("Couldn't retrieve JWK set from URL: Read timed out", e.getMessage());
		}
	}
	
	
	@Test
	public void retrying() throws KeySourceException {
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withStatus(404)
		.thenRespond()
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");
		
		final List<Event<RetryingJWKSetSource<SecurityContext>, SecurityContext>> retryingEvents = new LinkedList<>();
		
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(jwkSetURL)
			.retrying(new EventListener<RetryingJWKSetSource<SecurityContext>, SecurityContext>() {
				@Override
				public void notify(Event<RetryingJWKSetSource<SecurityContext>, SecurityContext> event) {
					retryingEvents.add(event);
				}
			})
			.build();
		
		// Retrieve and cache
		List<JWK> jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);
		
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		assertTrue(retryingEvents.get(0) instanceof RetryingJWKSetSource.RetrialEvent);
		assertEquals(1, retryingEvents.size());
	}
	
	
	@Test
	public void outage() throws KeySourceException {
		
		long outageTTL = JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE * 10;
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");
		
		final List<Event<OutageTolerantJWKSetSource<SecurityContext>, SecurityContext>> outageEvents = new LinkedList<>();
		
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(jwkSetURL)
			.outageTolerant(
				outageTTL,
				new EventListener<OutageTolerantJWKSetSource<SecurityContext>, SecurityContext>() {
					@Override
					public void notify(Event<OutageTolerantJWKSetSource<SecurityContext>, SecurityContext> event) {
						outageEvents.add(event);
					}
				}
			)
			.build();
		
		// Retrieve and cache
		List<JWK> jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		assertTrue(outageEvents.isEmpty());
		
		closeJadler();
		
		// Return from cache
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), CONTEXT);
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		assertTrue(outageEvents.isEmpty());
		
		// Unknown kid
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID("no-such-kid").build()), null);
		assertTrue(jwks.isEmpty());
		
		assertTrue(outageEvents.get(0) instanceof OutageTolerantJWKSetSource.OutageEvent);
		OutageTolerantJWKSetSource.OutageEvent outageEvent = (OutageTolerantJWKSetSource.OutageEvent) outageEvents.get(0);
		assertTrue(outageEvent.getException() instanceof KeySourceException);
		assertTrue(outageEvent.getException().getMessage().startsWith("Couldn't retrieve JWK set from URL: "));
		assertTrue(0 < outageEvent.getRemainingTime() && outageEvent.getRemainingTime() < outageTTL);
		assertEquals(1, outageEvents.size());
	}
	
	
	@Test
	public void failover() throws Exception {
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json")
		.thenRespond()
			.withStatus(500);
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/failover/jwks.json")
		.respond()
			.withStatus(200)
			.withBody(JWK_SET_1_2.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");
		
		JWKSource<SecurityContext> failoverSource = JWKSourceBuilder.create(new URL("http://localhost:" + port() + "/failover/jwks.json"))
			.build();
		
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(jwkSetURL)
			.failover(failoverSource)
			.build();
		
		// Retrieve and cache
		List<JWK> jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), null);
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		// Return from cache
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), CONTEXT);
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		// New kid, primary URL returns HTTP 500, resort to failover URL
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_2.getKeyID()).build()), null);
		assertEquals(Collections.singletonList(EC_JWK_2), jwks);
	}
	
	
	@Test
	public void healthReportListener() throws Exception {
		
		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
		.respond()
			.withStatus(200)
			.withBody(JWK_SET_1.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json")
		.thenRespond()
			.withStatus(404)
		.thenRespond()
			.withStatus(200)
			.withBody(JWK_SET_1_2.toString())
			.withEncoding(StandardCharset.UTF_8)
			.withContentType("application/json");
		
		final List<Event<CachingJWKSetSource<SecurityContext>, SecurityContext>> cacheEvents = new LinkedList<>();
		
		final AtomicReference<HealthReport<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext>> lastReport = new AtomicReference<>();
		
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(jwkSetURL)
			.rateLimited(false)
			.retrying(false)
			.cache(
				JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE,
				JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT,
				new EventListener<CachingJWKSetSource<SecurityContext>, SecurityContext>() {
					@Override
					public void notify(Event<CachingJWKSetSource<SecurityContext>, SecurityContext> event) {
						cacheEvents.add(event);
					}
				})
			.healthReporting(new HealthReportListener<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext>() {
				@Override
				public void notify(HealthReport<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> healthReport) {
					lastReport.set(healthReport);
				}
			})
			.build();
		
		assertNull(lastReport.get());
		
		// Retrieve and cache
		List<JWK> jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), CONTEXT);
		
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		assertTrue(cacheEvents.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(cacheEvents.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, cacheEvents.size());
		
		assertEquals(HealthStatus.HEALTHY, lastReport.get().getHealthStatus());
		assertEquals(CONTEXT, lastReport.get().getContext());
		
		// Return from cache
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_1.getKeyID()).build()), CONTEXT);
		
		assertEquals(Collections.singletonList(EC_JWK_1), jwks);
		
		assertEquals(HealthStatus.HEALTHY, lastReport.get().getHealthStatus());
		assertEquals(CONTEXT, lastReport.get().getContext());
		
		assertTrue(cacheEvents.get(0) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(cacheEvents.get(1) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(2, cacheEvents.size());
		
		// New kid, requires update, HTTP 404
		try {
			source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_2.getKeyID()).build()), CONTEXT);
			fail();
		} catch (KeySourceException e) {
			
			assertEquals("Couldn't retrieve JWK set from URL: http://localhost:" + port() + "/jwks.json", e.getMessage());
			
			assertTrue(cacheEvents.get(2) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
			assertEquals(3, cacheEvents.size());
			
			assertEquals(HealthStatus.NOT_HEALTHY, lastReport.get().getHealthStatus());
			assertEquals(e, lastReport.get().getException());
			assertEquals(CONTEXT, lastReport.get().getContext());
		}
		
		// JWKs URL endpoint recovers with HTTP 200
		jwks = source.get(new JWKSelector(new JWKMatcher.Builder().keyID(EC_JWK_2.getKeyID()).build()), CONTEXT);
		
		assertEquals(Collections.singletonList(EC_JWK_2), jwks);
		
		assertTrue(cacheEvents.get(3) instanceof CachingJWKSetSource.RefreshInitiatedEvent);
		assertTrue(cacheEvents.get(4) instanceof CachingJWKSetSource.RefreshCompletedEvent);
		assertEquals(5, cacheEvents.size());
		
		assertEquals(HealthStatus.HEALTHY, lastReport.get().getHealthStatus());
		assertEquals(CONTEXT, lastReport.get().getContext());
	}
}
