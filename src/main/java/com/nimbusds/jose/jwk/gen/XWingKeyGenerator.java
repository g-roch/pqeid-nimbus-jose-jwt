/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2026, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.jwk.gen;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.XWingKey;
import com.nimbusds.jose.util.Base64URL;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingKeyPairGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

import java.security.SecureRandom;


/**
 * PQEID: X-Wing hybrid post-quantum KEM (X25519 + ML-KEM-768) JWK generator.
 *
 * <p>Uses BouncyCastle's lightweight {@code org.bouncycastle.pqc.crypto.xwing}
 * API directly (no JCA {@code KeyPairGenerator}/{@code Provider} exists for
 * X-Wing) - the {@link #provider} setting from {@link JWKGenerator} is not
 * applicable and is ignored.
 */
public class XWingKeyGenerator extends JWKGenerator<XWingKey> {


	@Override
	public XWingKey generate()
		throws JOSEException {

		SecureRandom random = secureRandom != null ? secureRandom : new SecureRandom();

		XWingKeyPairGenerator generator = new XWingKeyPairGenerator();
		generator.init(new XWingKeyGenerationParameters(random));
		AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();

		XWingPublicKeyParameters pub = (XWingPublicKeyParameters) keyPair.getPublic();
		XWingPrivateKeyParameters priv = (XWingPrivateKeyParameters) keyPair.getPrivate();

		XWingKey xwKey = new XWingKey.Builder(Base64URL.encode(pub.getEncoded()))
			.d(Base64URL.encode(priv.getSeed()))
			.keyUse(use)
			.keyOperations(ops)
			.algorithm(alg)
			.keyID(kid)
			.expirationTime(exp)
			.notBeforeTime(nbf)
			.issueTime(iat)
			.keyStore(keyStore)
			.build();

		if (tprKid) {
			xwKey = new XWingKey.Builder(xwKey)
				.keyID(xwKey.computeThumbprint().toString())
				.build();
		}

		return xwKey;
	}
}
