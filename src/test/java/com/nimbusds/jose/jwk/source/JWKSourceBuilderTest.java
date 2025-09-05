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


import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;

import com.nimbusds.jose.util.events.Event;
import com.nimbusds.jose.util.events.EventListener;
import org.junit.Test;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.health.HealthReport;
import com.nimbusds.jose.util.health.HealthReportListener;


public class JWKSourceBuilderTest extends AbstractWrappedJWKSetSourceTest {
	
	
	@Test
	public void constants() {
		
		assertEquals(500L, JWKSourceBuilder.DEFAULT_HTTP_CONNECT_TIMEOUT);
		assertEquals(500L, JWKSourceBuilder.DEFAULT_HTTP_READ_TIMEOUT);
		assertEquals(50 * 1024L, JWKSourceBuilder.DEFAULT_HTTP_SIZE_LIMIT);
		assertEquals(5*60*1000L, JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE);
		assertEquals(15_000L, JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT);
		assertEquals(30_000L, JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME);
		assertEquals(30_000L, JWKSourceBuilder.DEFAULT_RATE_LIMIT_MIN_INTERVAL);
	}
	
	
	// peek into the jwk source and return the underlying sources
	@SuppressWarnings("resource")
	private static List<JWKSetSource<SecurityContext>> jwksSources(JWKSource<SecurityContext> jwkSource) {
		JWKSetBasedJWKSource<SecurityContext> remoteJWKSet = (JWKSetBasedJWKSource<SecurityContext>) jwkSource;
		
		JWKSetSource<SecurityContext> jwksProvider = remoteJWKSet.getJWKSetSource();
		
		List<JWKSetSource<SecurityContext>> list = new ArrayList<>();
		
		list.add(jwksProvider);
		
		while (jwksProvider instanceof JWKSetSourceWrapper) {
			JWKSetSourceWrapper<SecurityContext> baseJwksProvider = (JWKSetSourceWrapper<SecurityContext>) jwksProvider;
			jwksProvider = baseJwksProvider.getSource();
			list.add(jwksProvider);
		}
		
		return list;
	}
	
	@Test
	public void defaultBuild() {
		JWKSource<SecurityContext> source = builder().build();
		
		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(3, jwkSetSources.size());
		
		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof RateLimitedJWKSetSource);
		assertTrue(jwkSetSources.get(2) instanceof JWKSetSource);
		
		CachingJWKSetSource<SecurityContext> caching = (CachingJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE, caching.getTimeToLive());
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT, caching.getCacheRefreshTimeout());
		
		RateLimitedJWKSetSource rateLimited = (RateLimitedJWKSetSource) jwkSetSources.get(1);
		assertEquals(JWKSourceBuilder.DEFAULT_RATE_LIMIT_MIN_INTERVAL, rateLimited.getMinTimeInterval());
	}
	
	@Test
	public void caching_noRateLimiting() {
		JWKSource<SecurityContext> source = builder().rateLimited(false).cache(true).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);
		
		CachingJWKSetSource<SecurityContext> caching = (CachingJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE, caching.getTimeToLive());
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT, caching.getCacheRefreshTimeout());
	}
	
	@Test
	public void cachingForever_noRateLimiting() {
		JWKSource<SecurityContext> source = builder().rateLimited(false).cacheForever().build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);
		
		CachingJWKSetSource<SecurityContext> caching = (CachingJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(Long.MAX_VALUE, caching.getTimeToLive());
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT, caching.getCacheRefreshTimeout());
	}
	
	@Test
	public void cachingWithCustomSettings_noRateLimiting() {
		
		long oneDay = TimeUnit.HOURS.toMillis(25);
		long oneMinute = TimeUnit.MINUTES.toMillis(1);
		
		JWKSource<SecurityContext> source = builder().rateLimited(false).cache(oneDay, oneMinute).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());
		
		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);

		CachingJWKSetSource<SecurityContext> caching = (CachingJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(oneDay, caching.getTimeToLive());
		assertEquals(oneMinute, caching.getCacheRefreshTimeout());
	}
	
	@Test
	public void rateLimited() {
		JWKSource<SecurityContext> source = builder().rateLimited(true).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(3, jwkSetSources.size());
		
		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof RateLimitedJWKSetSource);
		assertTrue(jwkSetSources.get(2) instanceof JWKSetSource);
		
		RateLimitedJWKSetSource rateLimited = (RateLimitedJWKSetSource) jwkSetSources.get(1);
		assertEquals(JWKSourceBuilder.DEFAULT_RATE_LIMIT_MIN_INTERVAL, rateLimited.getMinTimeInterval());
	}
	
	@Test
	public void rateLimitedWithCustomSettings() {
		
		long minInterval = 60_000L;
		
		JWKSource<SecurityContext> source = builder().rateLimited(minInterval).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(3, jwkSetSources.size());
		
		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof RateLimitedJWKSetSource);
		assertTrue(jwkSetSources.get(2) instanceof JWKSetSource);
		
		RateLimitedJWKSetSource rateLimited = (RateLimitedJWKSetSource) jwkSetSources.get(1);
		assertEquals(minInterval, rateLimited.getMinTimeInterval());
	}
	
	@Test
	public void caching_rateLimited() {
		JWKSource<SecurityContext> source = builder().cache(true).rateLimited(true).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(3, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof RateLimitedJWKSetSource);
		assertTrue(jwkSetSources.get(2) instanceof JWKSetSource);
		
		CachingJWKSetSource<SecurityContext> caching = (CachingJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_TIME_TO_LIVE, caching.getTimeToLive());
		assertEquals(JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT, caching.getCacheRefreshTimeout());
		
		RateLimitedJWKSetSource rateLimited = (RateLimitedJWKSetSource) jwkSetSources.get(1);
		assertEquals(JWKSourceBuilder.DEFAULT_RATE_LIMIT_MIN_INTERVAL, rateLimited.getMinTimeInterval());
	}
	
	@Test
	public void cachingWithCustomSettings_rateLimitedWithCustomSettings() {
		
		long ttl = TimeUnit.DAYS.toMillis(2);
		long refreshTimeout = 5_000L;
		long rateLimitMinInterval = 10_000L;
		
		JWKSource<SecurityContext> source = builder()
			.cache(ttl, refreshTimeout)
			.rateLimited(rateLimitMinInterval)
			.build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(3, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof RateLimitedJWKSetSource);
		assertTrue(jwkSetSources.get(2) instanceof JWKSetSource);
		
		CachingJWKSetSource<SecurityContext> caching = (CachingJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(ttl, caching.getTimeToLive());
		assertEquals(refreshTimeout, caching.getCacheRefreshTimeout());
		
		RateLimitedJWKSetSource rateLimited = (RateLimitedJWKSetSource) jwkSetSources.get(1);
		assertEquals(rateLimitMinInterval, rateLimited.getMinTimeInterval());
	}

	@Test
	public void retrying() {
		JWKSource<SecurityContext> source = builder()
			.rateLimited(false)
			.cache(false)
			.refreshAheadCache(false)
			.retrying(true)
			.build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof RetryingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);
	}

	@Test
	public void outageTolerant() {
		JWKSource<SecurityContext> source = builder()
			.rateLimited(false)
			.cache(false)
			.refreshAheadCache(false)
			.outageTolerant(true)
			.build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof OutageTolerantJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);
	}

	@Test
	public void outageTolerantForever() {
		JWKSource<SecurityContext> source = builder()
			.rateLimited(false)
			.cache(false)
			.refreshAheadCache(false)
			.outageTolerantForever()
			.build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof OutageTolerantJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);
		
		assertEquals(Long.MAX_VALUE, ((OutageTolerantJWKSetSource<SecurityContext>) jwkSetSources.get(0)).getTimeToLive());
	}

	@Test
	public void outageTolerantWithCustomSettings() {
		
		long outageTTL = TimeUnit.DAYS.toMillis(25);
		
		JWKSource<SecurityContext> source = builder()
			.rateLimited(false)
			.cache(false)
			.refreshAheadCache(false)
			.outageTolerant(outageTTL)
			.build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		OutageTolerantJWKSetSource<SecurityContext> outageTolerant = (OutageTolerantJWKSetSource<SecurityContext>) jwkSetSources.get(0);
		assertEquals(outageTTL, outageTolerant.getTimeToLive());
	}

	@Test
	public void wrapCustomSource() {
		JWKSetSource<SecurityContext> customSource = mock(JWKSetSource.class);

		@SuppressWarnings("unchecked")
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(customSource).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(3, jwkSetSources.size());

		assertSame(jwkSetSources.get(jwkSetSources.size() - 1), customSource);
	}
	
	@Test
	public void refreshAheadCachingWithMinimalSetup() {
		JWKSource<SecurityContext> source = builder().rateLimited(false).refreshAheadCache(10 * 1000, true).build();

		List<JWKSetSource<SecurityContext>> jwksProviders = jwksSources(source);
		assertEquals(2, jwksProviders.size());

		assertTrue(jwksProviders.get(0) instanceof RefreshAheadCachingJWKSetSource);
		RefreshAheadCachingJWKSetSource<SecurityContext> refreshAheadSource = (RefreshAheadCachingJWKSetSource<SecurityContext>) jwksProviders.get(0);
		assertEquals(refreshAheadSource.getExecutorService().getClass(),
				RefreshAheadCachingJWKSetSource.createDefaultExecutorService().getClass());
		assertEquals(refreshAheadSource.getScheduledExecutorService().getClass(),
				RefreshAheadCachingJWKSetSource.createDefaultScheduledExecutorService().getClass());

		assertTrue(jwksProviders.get(1) instanceof JWKSetSource);
	}

	@Test
	public void refreshAheadCachingWithMaximalSetup() {
		ExecutorService executorService = mock(ExecutorService.class);
		ScheduledExecutorService scheduledExecutorService = mock(ScheduledExecutorService.class);

		JWKSource<SecurityContext> source = builder()
			.rateLimited(false)
			.refreshAheadCache(10 * 1000,
				new EventListener<CachingJWKSetSource<SecurityContext>, SecurityContext>() {
					@Override
					public void notify(Event<CachingJWKSetSource<SecurityContext>, SecurityContext> event) {
						// No-op
					}
				},
				executorService,
				false,
				scheduledExecutorService,
				false)
			.build();


		List<JWKSetSource<SecurityContext>> jwksProviders = jwksSources(source);
		assertEquals(2, jwksProviders.size());

		assertTrue(jwksProviders.get(0) instanceof RefreshAheadCachingJWKSetSource);
		RefreshAheadCachingJWKSetSource<SecurityContext> refreshAheadSource = (RefreshAheadCachingJWKSetSource<SecurityContext>) jwksProviders.get(0);
		assertSame(refreshAheadSource.getExecutorService(), executorService);
		assertSame(refreshAheadSource.getScheduledExecutorService(), scheduledExecutorService);
	}
	
	@Test
	public void all() {
		
		HealthReportListener<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> healthReportListener =
			new HealthReportListener<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext>() {
			
			@Override
			public void notify(HealthReport<JWKSetSourceWithHealthStatusReporting<SecurityContext>, SecurityContext> report) {
			
			}
		};
		
		JWKSource<SecurityContext> source = builder()
			.cache(true)
			.rateLimited(true)
			.retrying(true)
			.outageTolerant(true)
			.healthReporting(healthReportListener)
			.build();
		
		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(6, jwkSetSources.size());
		
		assertTrue(jwkSetSources.get(0) instanceof CachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof RateLimitedJWKSetSource);
		assertTrue(jwkSetSources.get(2) instanceof JWKSetSourceWithHealthStatusReporting);
		assertTrue(jwkSetSources.get(3) instanceof OutageTolerantJWKSetSource);
		assertTrue(jwkSetSources.get(4) instanceof RetryingJWKSetSource);
		assertTrue(jwkSetSources.get(5) instanceof JWKSetSource);
	}
	
	@Test
	public void failWhenRateLimitedWithoutCaching() {
		try {
			builder().cache(false).rateLimited(true).build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Rate limiting requires caching", e.getMessage());
		}
	}
	
	@Test
	public void failWhenRefreshAheadWithoutCaching() {
		try {
			builder().refreshAheadCache(true).cache(false).rateLimited(false).build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Refresh-ahead caching requires general caching", e.getMessage());
		}
	}
	
	@Test
	public void failWhenOutageTolerantWithForeverCacheTTL() {
		try {
			builder().refreshAheadCache(true).cache(false).rateLimited(false).build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Refresh-ahead caching requires general caching", e.getMessage());
		}
	}
	
	@Test
	public void failWhenOutageTolerantDueToNonExpiringCache() {
		try {
			builder().cacheForever().outageTolerant(Long.MAX_VALUE).build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Outage tolerance not necessary with a non-expiring cache", e.getMessage());
		}
	}
	
	@Test
	public void failWhenRefreshAheadDueToNonExpiringCache() {
		try {
			builder().cacheForever().refreshAheadCache(true).build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Refresh-ahead caching not necessary with a non-expiring cache", e.getMessage());
		}
	}

	@Test
	public void enableCacheWhenRefreshAhead() {
		JWKSource<SecurityContext> source = builder().rateLimited(false).cache(false).refreshAheadCache(true).build();

		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);
		assertEquals(2, jwkSetSources.size());

		assertTrue(jwkSetSources.get(0) instanceof RefreshAheadCachingJWKSetSource);
		assertTrue(jwkSetSources.get(1) instanceof JWKSetSource);
	}

	@Test
	public void fileURL() throws MalformedURLException {
		File file = new File("test");
		URL url = file.toURI().toURL();
		JWKSource<SecurityContext> source = JWKSourceBuilder.create(url).build();
		
		List<JWKSetSource<SecurityContext>> jwkSetSources = jwksSources(source);

		assertTrue(jwkSetSources.get(jwkSetSources.size() - 1) instanceof URLBasedJWKSetSource);
	}
}
