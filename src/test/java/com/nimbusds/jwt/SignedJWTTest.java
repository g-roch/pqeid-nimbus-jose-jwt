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

package com.nimbusds.jwt;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.JSONObjectUtilsTest;
import junit.framework.TestCase;

import java.net.URI;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;


public class SignedJWTTest extends TestCase {


	private static final RSAKey RSA_JWK;

	static {
                try {
                        RSA_JWK = new RSAKeyGenerator(2048).generate();
                } catch (JOSEException e) {
                        throw new RuntimeException(e);
                }
        }


	public void testCustomClaimsAreOrderedByInsertion()
		throws Exception {

		JWTClaimsSet claimsSetOne = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(new Date(123000L))
			.issuer("https://c2id.com")
			.claim("scope", "openid")
			.build();

		JWSSigner signer = new RSASSASigner(RSA_JWK.toRSAPrivateKey());
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetOne);
		jwt.sign(signer);
		String orderOne = jwt.serialize();

		JWTClaimsSet claimsSetTwo = new JWTClaimsSet.Builder()
			.subject("alice")
			.issuer("https://c2id.com")
			.issueTime(new Date(123000L))
			.claim("scope", "openid")
			.build();

		jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetTwo);
		jwt.sign(signer);
		String orderTwo = jwt.serialize();
		assertNotSame(orderOne, orderTwo);
	}


	public void testSignAndVerify()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(new Date(123000L))
			.issuer("https://c2id.com")
			.claim("scope", "openid")
			.build();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			jwkURL(new URI("https://c2id.com/jwks.json")).
			build();

		SignedJWT jwt = new SignedJWT(header, claimsSet);

		assertEquals(JWSObject.State.UNSIGNED, jwt.getState());
		assertEquals(header, jwt.getHeader());
		assertEquals("alice", jwt.getJWTClaimsSet().getSubject());
		assertEquals(123000L, jwt.getJWTClaimsSet().getIssueTime().getTime());
		assertEquals("https://c2id.com", jwt.getJWTClaimsSet().getIssuer());
		assertEquals("openid", jwt.getJWTClaimsSet().getStringClaim("scope"));
		assertNull(jwt.getSignature());

		Base64URL sigInput = Base64URL.encode(jwt.getSigningInput());

		JWSSigner signer = new RSASSASigner(RSA_JWK.toRSAPrivateKey());

		jwt.sign(signer);

		assertEquals(JWSObject.State.SIGNED, jwt.getState());
		assertNotNull(jwt.getSignature());

		String serializedJWT = jwt.serialize();

		jwt = SignedJWT.parse(serializedJWT);
		assertEquals(serializedJWT, jwt.getParsedString());

		assertEquals(JWSObject.State.SIGNED, jwt.getState());
		assertNotNull(jwt.getSignature());
		assertEquals(sigInput, Base64URL.encode(jwt.getSigningInput()));

		JWSVerifier verifier = new RSASSAVerifier(RSA_JWK.toRSAPublicKey());
		assertTrue(jwt.verify(verifier));
	}


	public void testClaimsSetConstructor_serializeNullClaims_enable()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issuer(null)
			.claim("xxx", null)
			.serializeNullClaims(true)
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);

		Map<String, Object> jsonObject = jwt.getJWTClaimsSet().toJSONObject(true);
		assertEquals("alice", jsonObject.get("sub"));
		assertTrue(jsonObject.containsKey("iss"));
		assertNull(jsonObject.get("iss"));
		assertTrue(jsonObject.containsKey("xxx"));
		assertNull(jsonObject.get("xxx"));
		assertEquals(3, jsonObject.size());

		jwt.sign(new RSASSASigner(RSA_JWK.toRSAPrivateKey()));

		String jwtString = jwt.serialize();

		jwt = SignedJWT.parse(jwtString);

		jsonObject = jwt.getJWTClaimsSet().toJSONObject(true);
		assertEquals("alice", jsonObject.get("sub"));
		assertTrue(jsonObject.containsKey("iss"));
		assertNull(jsonObject.get("iss"));
		assertTrue(jsonObject.containsKey("xxx"));
		assertNull(jsonObject.get("xxx"));
		assertEquals(3, jsonObject.size());
	}


	public void testClaimsSetConstructor_serializeNullClaims_default_disable()
		throws Exception {

		List<JWTClaimsSet> variants = Arrays.asList(
			new JWTClaimsSet.Builder()
				.subject("alice")
				.issuer(null)
				.claim("xxx", null)
				.build(),
			new JWTClaimsSet.Builder()
				.subject("alice")
				.issuer(null)
				.claim("xxx", null)
				.serializeNullClaims(false)
				.build());

		for (JWTClaimsSet claimsSet: variants) {

			SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);

			Map<String, Object> jsonObject = jwt.getJWTClaimsSet().toJSONObject();
			assertEquals("alice", jsonObject.get("sub"));
			assertEquals(1, jsonObject.size());

			jwt.sign(new RSASSASigner(RSA_JWK.toRSAPrivateKey()));

			String jwtString = jwt.serialize();

			jwt = SignedJWT.parse(jwtString);

			jsonObject = jwt.getJWTClaimsSet().toJSONObject(true);
			assertEquals("alice", jsonObject.get("sub"));
			assertEquals(1, jsonObject.size());
		}
	}
	
	
	public void testTrimWhitespace()
		throws Exception {
		
		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
		jwt.sign(new MACSigner(secret));
		
		String jwtString = " " + jwt.serialize() + " ";
		
		jwt = SignedJWT.parse(jwtString);
		assertTrue(jwt.verify(new MACVerifier(secret)));
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/252/respect-explicit-set-of-null-claims
	public void testSignedJWTWithNullClaimValue()
		throws Exception {
		
		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.claim("myclaim", null)
			.build();
		
		JWSObject jwsObject = new JWSObject(
			new JWSHeader(JWSAlgorithm.HS256),
			new Payload(claimsSet.toJSONObject(true))
		);
		
		jwsObject.sign(new MACSigner(secret));
		
		SignedJWT jwt = SignedJWT.parse(jwsObject.serialize());
		assertTrue(jwt.verify(new MACVerifier(secret)));
		
		claimsSet = jwt.getJWTClaimsSet();
		assertEquals("alice", claimsSet.getSubject());
		assertNull(claimsSet.getClaim("myclaim"));
		assertTrue(claimsSet.getClaims().containsKey("myclaim"));
		assertEquals(2, claimsSet.getClaims().size());
	}

	
	public void testPayloadUpdated()
			throws Exception {

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder()
				.subject("before").build());

		assertEquals("before", jwt.getJWTClaimsSet().getSubject());

		jwt.setPayload(new Payload(new JWTClaimsSet.Builder()
				.subject("after").build().toJSONObject()));

		assertEquals("after", jwt.getJWTClaimsSet().getSubject());
	}
	
	
	public void testParseWithExcessiveMixedNestingInPayload() throws ParseException {
		
		StringBuilder sb = new StringBuilder("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhIjpb");
		for (int i = 0; i < 1000; i++) {
			sb.append("W1tb");
		}
		sb.append(".aaaa");
		
		SignedJWT jwt = SignedJWT.parse(sb.toString());
		
		try {
			jwt.getJWTClaimsSet();
			fail();
		} catch (ParseException e) {
			assertEquals("Payload of JWS object is not a valid JSON object", e.getMessage());
		}
	}
	
	
	public void testParseWithMissingRequiredHeader() {
		
		Base64URL header = Base64URL.encode("{}");
		Base64URL payload = new JWTClaimsSet.Builder().subject("alice").build().toPayload().toBase64URL();
		Base64URL signature = Base64URL.encode("invalid-signature");
		
		String illegalJWT = header + "." + payload + "." + signature;
		
		try {
			SignedJWT.parse(illegalJWT);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JWS header: Missing \"alg\" in header JSON object", e.getMessage());
		}
	}


	public void testParseWithExcessiveNesting()
                throws JOSEException, ParseException {

		JWSObject jwsObject = new JWSObject(
			new JWSHeader(JWSAlgorithm.RS256),
			new Payload(JSONObjectUtilsTest.createJSONObjectWithNesting(255))
		);

		jwsObject.sign(new RSASSASigner(RSA_JWK));

		String jwtString = jwsObject.serialize();

		SignedJWT signedJWT = SignedJWT.parse(jwtString);
		try {
			signedJWT.getJWTClaimsSet();
			fail();
		} catch (ParseException e) {
			assertEquals("Payload of JWS object is not a valid JSON object", e.getMessage());
		}
	}
}
