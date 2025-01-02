package com.nimbusds.jose.crypto.factories;

import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.JWSObject.State;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.jca.JCAAware;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jose.util.ByteUtils;

import junit.framework.TestCase;

/**
 * Test the default implementation of the JWS Signer Factory against
 * HMAC, RSA, EC, and ED keys. Creates signers and signs JWS objects
 * with them, checks that object is in SIGNED state.
 *
 * @author Justin Richer
 */
public class DefaultJWSSignerFactoryTest extends TestCase {


	private DefaultJWSSignerFactory factory;

	@Override
	protected void setUp() {
		this.factory = new DefaultJWSSignerFactory();
	}

	public void testInterfaces() {
		assertTrue(factory instanceof JWSSignerFactory);
		assertTrue(factory instanceof JCAAware);
		assertTrue(factory instanceof JWSProvider);
	}

	public void testDefaultJCAContext() {
		assertNotNull(factory.getJCAContext().getSecureRandom());
		assertNull(factory.getJCAContext().getProvider());
	}

	public void testAlgSupport() {
		assertTrue(factory.supportedJWSAlgorithms().containsAll(JWSAlgorithm.Family.HMAC_SHA));
		assertTrue(factory.supportedJWSAlgorithms().containsAll(JWSAlgorithm.Family.RSA));
		assertTrue(factory.supportedJWSAlgorithms().containsAll(JWSAlgorithm.Family.EC));
		assertTrue(factory.supportedJWSAlgorithms().containsAll(Ed25519Signer.SUPPORTED_ALGORITHMS));
		assertEquals(JWSAlgorithm.Family.HMAC_SHA.size()
			+ JWSAlgorithm.Family.RSA.size()
			+ JWSAlgorithm.Family.EC.size()
			+ Ed25519Signer.SUPPORTED_ALGORITHMS.size()
			, factory.supportedJWSAlgorithms().size());
	}

	public void testSetSecureRandom()
		throws Exception {

		SecureRandom secureRandom = new SecureRandom() {
			@Override
			public String getAlgorithm() {
				return "test";
			}
		};

		factory.getJCAContext().setSecureRandom(secureRandom);

		KeyGenerator keyGen = KeyGenerator.getInstance("HMACSHA256");
		SecretKey key = keyGen.generateKey();
		assertEquals(256, ByteUtils.bitLength(key.getEncoded()));

		JWK jwk = new OctetSequenceKey.Builder(key).build();

		JWSSigner signer = factory.createJWSSigner(jwk, JWSAlgorithm.HS256);

		assertEquals("test", signer.getJCAContext().getSecureRandom().getAlgorithm());
	}

	public void testSetProvider()
		throws Exception {

		factory.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		KeyGenerator keyGen = KeyGenerator.getInstance("HMACSHA256");
		SecretKey key = keyGen.generateKey();
		assertEquals(256, ByteUtils.bitLength(key.getEncoded()));

		JWK jwk = new OctetSequenceKey.Builder(key).build();

		JWSSigner signer = factory.createJWSSigner(jwk, JWSAlgorithm.HS256);

		assertEquals("BC", signer.getJCAContext().getProvider().getName());
	}

	public void testRsaSigner()
		throws Exception {

		// test that we can sign a JWS object with an RSA key using the factory method to get the signer

		String keyString = 
			"{" +
			"    \"p\": \"62KMqaxMEh_dji-v3c3DUlFa7P0G4j4aeOZko1P88JG-vNocGQWeVFy3c5PA9nMaW2qUIivyaHLElkhaQxRUeGGy7kz5WtNOoqunJ2HyrLXlQyQvkcDIxfeiO2mooTB17S0YduW8uvsA2XE2VJv1U7ZoDGlopXT8ONZLl43JqA0\"," +
			"    \"kty\": \"RSA\"," +
			"    \"q\": \"l46sljvMwpbPA2t3retPD5l0qLKdZRtB7EKyH6eAO31frNeh8jfijvlame8PUL2VAUchylCQspl7tmeLpT0HJOTYiFsyLgRtCQlXgfc69Qqu72cosMEhGINXQLNwGt7vc-4bMhr94ThoitJspfKASDcvWV7AThlYlX54ijdVB68\"," +
			"    \"d\": \"hIb8sp24ZtpFPTg7ge3j2y20SxsBOOsN0PhMWFjg3zW-qCwoAz2KIeeUMrMaL5_5CiLuTTVTW1eAeJJErJWdc7l7IE5RhXpUYe_ZBM2ipG0ZgLBjtahtxm32eEo_0zFHhK9sGD8XwEeaiTl2VXeODvoE87Sh4N8wJlgc_u_x8P3LW4_i0xOL-IOt0BS79JNSO7_eDsZi7I9WjS7ro5T5yLbBjAEbizIoW1Qp2mxOIao7bWqbAq_5sxZMo5gLnCokW1hl_tcEujEkEbBOE-gCGiD_2naXV328tmOf4nhhlkEo9chDMbkcmcHHAE2tBHGFMhLbTxYv2FMIeka5DO4emQ\"," +
			"    \"e\": \"AQAB\"," +
			"    \"qi\": \"snXfLJYGdtPvPtp1PAk0yLXgMSmgXLSb9rRdDndPJlZyQ8hTMvQq3z04h9_ThDYj43R0Z90HPsTM7-8Mfrw-AgDabr5UYaSciHA9Kl-BPjuuWeMzKwSAgnkCiEbWvAbBw77QgE_FA1cWF3R2Ni5M_mw2OSlbO6jlMrhFIo233VQ\"," +
			"    \"dp\": \"245--j0Wb8l9VYUxm8i0KfJsx6V0aE_ZTXBJ6vcKdjLcITepAcX122boT0xAryDKMv8E0aMAZ2C18h_m4a7y457t0c3GwWtca-uE7P016Nd509jK7j9OhynnD1gMzN1xAhwQN8cu9ZHvRuOM8_rNKJp6Dym7TKoEIdfxhpngwXk\"," +
			"    \"dq\": \"X1Pojp6SjprZHyeLoaNumTtGu42NnrjkYD0bWPm8mK6lbUw8muQ35wJE0Kojkf-NJ76cLGs8eHo97F944LhgM_6VjD8Acx1pj9OGbUManGLZ4c-bMoJn1MlYKmQzUVOEfgD4ri14Hx-h8h-lI0RDGClN6QLGJtmedHmWTCm9nBU\"," +
			"    \"n\": \"i1pQUnP61-90tXQEAFFh7Z0Vi-XxttlQ0iARSVV5qizJRNrsbQhKSrQiGbvg-dXiwYfpGQ66LGEpxKSxtoMbfOeibM9llBlK6D1khbbHnk8sYRbsw_BCG4bJechHp6WVUsFJrCpOTvtoPowI6rPs61pCV1IqjOEBgWdb9tYSTE_ABkEd6OdQCqwmss-hvmqoQ7Hb4B5jugZavPbgGw5-CWlqHL30rw8FjoQgoybMSQXNUzROH7TAxbHc8yWQeGKUF-7v6mfSG1G-JPBEsav_y47td-5ZuQB9Ow-oU2WqdnHbv3oY655KiquRj4PND0TKoZ4bQvsFww6cN-eMB8M74w\"" +
			"}";

		JWK key = JWK.parse(keyString);

		JWSObject jwsObject = testSignerWithAlg(key, JWSAlgorithm.RS256, RSASSASigner.class);
		assertTrue(jwsObject.verify(new RSASSAVerifier(key.toRSAKey())));

		JWSObject jwsObject2 = testSignerNoAlg(key, JWSAlgorithm.RS256, RSASSASigner.class);
		assertTrue(jwsObject2.verify(new RSASSAVerifier(key.toRSAKey())));
	}

	public void testHmacSigner()
		throws Exception {

		// test that we can sign a JWS object with an octet key using the factory method to get the signer

		String keyString = 
			"{" +
			"    \"kty\": \"oct\"," +
			"    \"k\": \"XG_TrsgfEf78uHg2VrhSB29Y8wXSbWYqiItsD-MDqwYChZYwcc1POEBGZ0tY3BcPRHM53LIcvCCa8msinAjCc61pT_upklOM2YIcmZqni7wA4XL-cmjmNae20zJYAMV8-2PIUnscIfv_9vJ9eJvwcClYKDsSeBNdiEE92oG9VZ-gArZplpHIHhiu5r9oRaxibe-wwRCmsWBRJ5-TQVjBvwrhAKFvkxrT_14ofnXX9pfojuWlWZlP4te7AGsEEhTSxMqsydo85H9jbkWRJV73AgGMh4c_Ul-D99h5TIuDtUNv6ViamK9k5h46c3JP9nm54V0ijkHYuDXwVJOwa8Tkeg\"" +
			"}";

		JWK key = JWK.parse(keyString);

		JWSObject jwsObject = testSignerWithAlg(key, JWSAlgorithm.HS256, MACSigner.class);
		assertTrue(jwsObject.verify(new MACVerifier(key.toOctetSequenceKey())));

		JWSObject jwsObject2 = testSignerNoAlg(key, JWSAlgorithm.HS256, MACSigner.class);
		assertTrue(jwsObject2.verify(new MACVerifier(key.toOctetSequenceKey())));
	}

	public void testEcSigner()
		throws Exception {

		// test that we can sign a JWS object with an EC key using the factory method to get the signer

		String keyString = 
			"{" +
			"    \"kty\": \"EC\"," +
			"    \"crv\": \"P-256\"," +
			"    \"x\": \"Wbhp2pxZqaKCzOu6GrFB2WUvA0fQ66Yzuxp_gT6-pQU\"," +
			"    \"y\": \"S1pm56MktnjQWUK8Pk-gLOqTqJY2nG3tIznRtLjp7YQ\"," +
			"    \"d\": \"8HXxg8NF7ywPyTCpuAKWfVXSpF1vAaCQrVCNPj-8Tqk\"" +
			"}";

		JWK key = JWK.parse(keyString);

		JWSObject jwsObject = testSignerWithAlg(key, JWSAlgorithm.ES256, ECDSASigner.class);
		assertTrue(jwsObject.verify(new ECDSAVerifier(key.toECKey())));

		JWSObject jwsObject2 = testSignerNoAlg(key, JWSAlgorithm.ES256, ECDSASigner.class);
		assertTrue(jwsObject2.verify(new ECDSAVerifier(key.toECKey())));
	}

	public void testEdSigner_Ed25519()
		throws Exception {

		// test that we can sign a JWS object with an octet pair key using the factory method to get the signer

		String keyString =
			"{" +
			"    \"kty\": \"OKP\"," +
			"    \"crv\": \"Ed25519\"," +
			"    \"x\": \"iEf21rMa-4kr_m5MaLUbu7dGuyu5n312lI14WM6xsSs\"," +
			"    \"d\": \"2nNrpmRJEUBs7NhrsSYttOyJhMXSS1LLrEK60_a88hQ\"" +
			"}";

		JWK key = JWK.parse(keyString);

		for (JWSAlgorithm alg: Arrays.asList(JWSAlgorithm.EdDSA, JWSAlgorithm.Ed25519)) {

			JWSObject jwsObject = testSignerWithAlg(key, alg, Ed25519Signer.class);
			assertTrue(jwsObject.verify(new Ed25519Verifier(key.toOctetKeyPair().toPublicJWK())));

			JWSObject jwsObject2 = testSignerNoAlg(key, alg, Ed25519Signer.class);
			assertTrue(jwsObject2.verify(new Ed25519Verifier(key.toOctetKeyPair().toPublicJWK())));
		}
	}

	public void testEdSigner_Ed448()
		throws Exception {

		// test that we can sign a JWS object with an octet pair key using the factory method to get the signer

		String keyString =
			"{" +
			"    \"kty\": \"OKP\"," +
			"    \"crv\": \"Ed448\"," +
			"    \"alg\": \"EdDSA\"," +
			"    \"x\": \"k6kVOMk4vlVhzCzXV4d-wKXQIXE7hZ8gnEo_lJbUG95vfGygabmkWNTYx69cTpXAWOKJseKrSEGA\"," +
			"    \"d\": \"VlZe-glDfDIsGT1vqdOIDNOqt0OoG3cDj18FteGe6w31ox1xY_tvlF9AVJRLppwZ3k-VRcu6X47I\"" +
			"}";

		JWK key = JWK.parse(keyString);

		for (JWSAlgorithm alg: Arrays.asList(JWSAlgorithm.EdDSA, JWSAlgorithm.Ed448)) {

			try {
				testSignerWithAlg(key, alg, Ed25519Signer.class);
				fail();
			} catch (JOSEException e) {
				assertEquals("Unsupported JWK type, JWK curve and / or JWS algorithm", e.getMessage());
			}

			try {
				testSignerNoAlg(key, alg, Ed25519Signer.class);
				fail();
			} catch (JOSEException e) {
				assertEquals("Unsupported JWK type and / or curve", e.getMessage());
			}
		}
	}

	private JWSObject testSignerWithAlg(JWK key, JWSAlgorithm alg, Class<? extends JWSSigner> c) throws JOSEException {
		JWSSigner signer = factory.createJWSSigner(key, alg);

		return testSignerInternal(alg, c, signer);
	}

	private JWSObject testSignerNoAlg(JWK key, JWSAlgorithm alg, Class<? extends JWSSigner> c) throws JOSEException {
		JWSSigner signer = factory.createJWSSigner(key);

		return testSignerInternal(alg, c, signer);
	}

	private JWSObject testSignerInternal(JWSAlgorithm alg, Class<? extends JWSSigner> c, JWSSigner signer) throws JOSEException {
		assertEquals(c, signer.getClass());

		JWSHeader header = new JWSHeader(alg);

		JWSObject jwsObject = new JWSObject(header, new Payload("Hello world!"));

		assertEquals(State.UNSIGNED, jwsObject.getState());

		jwsObject.sign(signer);

		assertEquals(State.SIGNED, jwsObject.getState());

		return jwsObject;
	}

	public void testRejectEncryptionOctKey() throws ParseException, JOSEException {
		
		String keyString = 
			"{" +
			"    \"kty\": \"oct\"," +
			"    \"use\": \"enc\"," +
			"    \"k\": \"XG_TrsgfEf78uHg2VrhSB29Y8wXSbWYqiItsD-MDqwYChZYwcc1POEBGZ0tY3BcPRHM53LIcvCCa8msinAjCc61pT_upklOM2YIcmZqni7wA4XL-cmjmNae20zJYAMV8-2PIUnscIfv_9vJ9eJvwcClYKDsSeBNdiEE92oG9VZ-gArZplpHIHhiu5r9oRaxibe-wwRCmsWBRJ5-TQVjBvwrhAKFvkxrT_14ofnXX9pfojuWlWZlP4te7AGsEEhTSxMqsydo85H9jbkWRJV73AgGMh4c_Ul-D99h5TIuDtUNv6ViamK9k5h46c3JP9nm54V0ijkHYuDXwVJOwa8Tkeg\"" +
			"}";
		
		JWK key = JWK.parse(keyString);
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key, JWSAlgorithm.RS256);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
	}

	public void testRejectEncryptionRSAKey() throws ParseException, JOSEException {
		
		String keyString = 
			"{" +
			"    \"p\": \"62KMqaxMEh_dji-v3c3DUlFa7P0G4j4aeOZko1P88JG-vNocGQWeVFy3c5PA9nMaW2qUIivyaHLElkhaQxRUeGGy7kz5WtNOoqunJ2HyrLXlQyQvkcDIxfeiO2mooTB17S0YduW8uvsA2XE2VJv1U7ZoDGlopXT8ONZLl43JqA0\"," +
			"    \"kty\": \"RSA\"," +
			"    \"use\": \"enc\"," +
			"    \"q\": \"l46sljvMwpbPA2t3retPD5l0qLKdZRtB7EKyH6eAO31frNeh8jfijvlame8PUL2VAUchylCQspl7tmeLpT0HJOTYiFsyLgRtCQlXgfc69Qqu72cosMEhGINXQLNwGt7vc-4bMhr94ThoitJspfKASDcvWV7AThlYlX54ijdVB68\"," +
			"    \"d\": \"hIb8sp24ZtpFPTg7ge3j2y20SxsBOOsN0PhMWFjg3zW-qCwoAz2KIeeUMrMaL5_5CiLuTTVTW1eAeJJErJWdc7l7IE5RhXpUYe_ZBM2ipG0ZgLBjtahtxm32eEo_0zFHhK9sGD8XwEeaiTl2VXeODvoE87Sh4N8wJlgc_u_x8P3LW4_i0xOL-IOt0BS79JNSO7_eDsZi7I9WjS7ro5T5yLbBjAEbizIoW1Qp2mxOIao7bWqbAq_5sxZMo5gLnCokW1hl_tcEujEkEbBOE-gCGiD_2naXV328tmOf4nhhlkEo9chDMbkcmcHHAE2tBHGFMhLbTxYv2FMIeka5DO4emQ\"," +
			"    \"e\": \"AQAB\"," +
			"    \"qi\": \"snXfLJYGdtPvPtp1PAk0yLXgMSmgXLSb9rRdDndPJlZyQ8hTMvQq3z04h9_ThDYj43R0Z90HPsTM7-8Mfrw-AgDabr5UYaSciHA9Kl-BPjuuWeMzKwSAgnkCiEbWvAbBw77QgE_FA1cWF3R2Ni5M_mw2OSlbO6jlMrhFIo233VQ\"," +
			"    \"dp\": \"245--j0Wb8l9VYUxm8i0KfJsx6V0aE_ZTXBJ6vcKdjLcITepAcX122boT0xAryDKMv8E0aMAZ2C18h_m4a7y457t0c3GwWtca-uE7P016Nd509jK7j9OhynnD1gMzN1xAhwQN8cu9ZHvRuOM8_rNKJp6Dym7TKoEIdfxhpngwXk\"," +
			"    \"dq\": \"X1Pojp6SjprZHyeLoaNumTtGu42NnrjkYD0bWPm8mK6lbUw8muQ35wJE0Kojkf-NJ76cLGs8eHo97F944LhgM_6VjD8Acx1pj9OGbUManGLZ4c-bMoJn1MlYKmQzUVOEfgD4ri14Hx-h8h-lI0RDGClN6QLGJtmedHmWTCm9nBU\"," +
			"    \"n\": \"i1pQUnP61-90tXQEAFFh7Z0Vi-XxttlQ0iARSVV5qizJRNrsbQhKSrQiGbvg-dXiwYfpGQ66LGEpxKSxtoMbfOeibM9llBlK6D1khbbHnk8sYRbsw_BCG4bJechHp6WVUsFJrCpOTvtoPowI6rPs61pCV1IqjOEBgWdb9tYSTE_ABkEd6OdQCqwmss-hvmqoQ7Hb4B5jugZavPbgGw5-CWlqHL30rw8FjoQgoybMSQXNUzROH7TAxbHc8yWQeGKUF-7v6mfSG1G-JPBEsav_y47td-5ZuQB9Ow-oU2WqdnHbv3oY655KiquRj4PND0TKoZ4bQvsFww6cN-eMB8M74w\"" +
			"}";
		
		JWK key = JWK.parse(keyString);
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key, JWSAlgorithm.RS256);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
	}

	public void testRejectEncryptionECKey() throws ParseException, JOSEException {
		
		String keyString = 
			"{" +
			"    \"kty\": \"EC\"," +
			"    \"use\": \"enc\"," +
			"    \"d\": \"8HXxg8NF7ywPyTCpuAKWfVXSpF1vAaCQrVCNPj-8Tqk\"," +
			"    \"crv\": \"P-256\"," +
			"    \"x\": \"Wbhp2pxZqaKCzOu6GrFB2WUvA0fQ66Yzuxp_gT6-pQU\"," +
			"    \"y\": \"S1pm56MktnjQWUK8Pk-gLOqTqJY2nG3tIznRtLjp7YQ\"" +
			"}";
		
		JWK key = JWK.parse(keyString);
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key, JWSAlgorithm.RS256);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
	}

	public void testRejectEncryptionOKPKey() throws ParseException, JOSEException {
		
		String keyString = 
			"{" +
			"    \"kty\": \"OKP\"," +
			"    \"crv\": \"Ed25519\"," +
			"    \"use\": \"enc\"," +
			"    \"x\": \"iEf21rMa-4kr_m5MaLUbu7dGuyu5n312lI14WM6xsSs\"," +
			"    \"d\": \"2nNrpmRJEUBs7NhrsSYttOyJhMXSS1LLrEK60_a88hQ\"" +
			"}";
		
		JWK key = JWK.parse(keyString);
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
		
		try {
			new DefaultJWSSignerFactory().createJWSSigner(key, JWSAlgorithm.RS256);
			fail();
		} catch (JWKException e) {
			assertEquals("The JWK use must be sig (signature) or unspecified", e.getMessage());
		}
	}
}
