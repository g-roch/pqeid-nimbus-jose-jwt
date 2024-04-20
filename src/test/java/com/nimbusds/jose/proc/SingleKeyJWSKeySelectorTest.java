package com.nimbusds.jose.proc;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SingleKeyJWSKeySelectorTest {

	private final Key key = new SecretKeySpec(new byte[] { 0 }, "mock");
	private final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
	private final SingleKeyJWSKeySelector<SecurityContext> keySelector =
			new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);

	@Test
	public void testThatSelectJWSKeysReturnsKey() {
		JWSHeader jwsHeader = new JWSHeader(this.jwsAlgorithm);
		List<? extends Key> keys = this.keySelector.selectJWSKeys(jwsHeader, null);
		assertEquals(keys.size(), 1);
		assertEquals(keys.get(0), this.key);
	}

	@Test
	public void testThatSelectJWSKeysVerifiesAlgorithmInHeader() {
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.EdDSA);
		assertTrue("Expected empty list", this.keySelector.selectJWSKeys(jwsHeader, null).isEmpty());
	}

	@Test(expected = NullPointerException.class)
	public void testThatConstructorDoesNotAllowNullAlgorithm() {
		new SingleKeyJWSKeySelector<>(null, this.key);
	}

	@Test(expected = NullPointerException.class)
	public void testThatConstructorDoesNotAllowNullKeys() {
		new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, null);
	}
}