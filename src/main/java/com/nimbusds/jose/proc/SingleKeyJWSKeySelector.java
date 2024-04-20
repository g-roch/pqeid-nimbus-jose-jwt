package com.nimbusds.jose.proc;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Objects;


/**
 * A {@link JWSKeySelector} that always returns the same {@link Key}.
 *
 * @author Josh Cummings
 * @version 2024-04-20
 */
public class SingleKeyJWSKeySelector<C extends SecurityContext> implements JWSKeySelector<C> {
	
	
	private final List<Key> singletonKeyList;
	
	private final JWSAlgorithm expectedJWSAlg;
	

	/**
	 * Creates a new single-key JWS key selector.
	 *
	 * @param expectedJWSAlg The expected JWS algorithm for the JWS
	 *                       objects to be verified. Must not be
	 *                       {@code null}.
	 * @param key            The key to always return. Must not be
	 *                       {@code null}.
	 */
	public SingleKeyJWSKeySelector(final JWSAlgorithm expectedJWSAlg, final Key key) {
		this.singletonKeyList = Collections.singletonList(Objects.requireNonNull(key));
		this.expectedJWSAlg = Objects.requireNonNull(expectedJWSAlg);
	}

	
	@Override
	public List<? extends Key> selectJWSKeys(final JWSHeader header, final C context) {
		
		if (! this.expectedJWSAlg.equals(header.getAlgorithm())) {
			return Collections.emptyList();
		}
		
		return this.singletonKeyList;
	}
}
