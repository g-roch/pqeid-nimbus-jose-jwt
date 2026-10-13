package com.nimbusds.jose.jwk;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.net.URI;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * PQEID: composite PQ/T hybrid signature key, {@code kty} "AKP"
 * (draft-ietf-jose-pq-composite-sigs-04, section 4.1).
 *
 * <ul>
 *   <li>{@code pub}  = ML-DSA public key || ECDSA public key (X9.62 uncompressed, 0x04 || x || y)
 *   <li>{@code priv} = ML-DSA 32-byte seed || ECPrivateKey (RFC 5915, 51 bytes for P-256)
 * </ul>
 *
 * <p>BouncyCastle 1.84 stores composite keys in exactly these encodings (LAMPS), so converting
 * to JCA keys only wraps the bytes in SubjectPublicKeyInfo / PKCS#8 with the composite OID
 * (proven against the draft's official example, my_learning_guide.md section 24.3).
 *
 * <p>Data-based keys only: no X.509 certificate or KeyStore support in this PoC.
 */
public final class CompositeMLDSAKey extends AKPJWK {

    private static final long serialVersionUID = 1L;

    /** LAMPS composite OIDs (BC 1.84), per JOSE algorithm. */
    private static final Map<JWSAlgorithm, String> OIDS =
            Map.of(JWSAlgorithm.ML_DSA_65_ES256, "1.3.6.1.5.5.7.6.45");

    /** Expected encoded lengths: ML-DSA-65 pub 1952 + EC point 65; seed 32 + ECPrivateKey 51. */
    private static final Map<JWSAlgorithm, Integer> PUB_LEN =
            Map.of(JWSAlgorithm.ML_DSA_65_ES256, 2017);
    private static final Map<JWSAlgorithm, Integer> PRIV_LEN =
            Map.of(JWSAlgorithm.ML_DSA_65_ES256, 83);
    private static final Map<JWSAlgorithm, Integer> PQ_PUB_LEN =
            Map.of(JWSAlgorithm.ML_DSA_65_ES256, 1952);

    private final byte[] publicData;
    private final byte[] privateData;   // null for a public key

    public CompositeMLDSAKey(final JWSAlgorithm alg,
                             final byte[] publicData,
                             final byte[] privateData,
                             final KeyUse use,
                             final Set<KeyOperation> ops,
                             final String kid,
                             final URI x5u,
                             final Base64URL x5t,
                             final Base64URL x5t256,
                             final List<Base64> x5c,
                             final Date exp,
                             final Date nbf,
                             final Date iat,
                             final KeyRevocation revocation) {
        super(use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, null);
        if (!JWSAlgorithm.Family.ML_COMPOSITE.contains(alg)) {
            throw new IllegalArgumentException("Not a composite ML-DSA algorithm: " + alg);
        }
        Objects.requireNonNull(publicData, "publicData");
        if (publicData.length != PUB_LEN.get(alg) || publicData[PQ_PUB_LEN.get(alg)] != 0x04) {
            throw new IllegalArgumentException("Invalid composite public key for " + alg);
        }
        if (privateData != null && privateData.length != PRIV_LEN.get(alg)) {
            throw new IllegalArgumentException("Invalid composite private key length for " + alg);
        }
        this.publicData = publicData.clone();
        this.privateData = privateData == null ? null : privateData.clone();
    }

    public static CompositeMLDSAKey parse(final Map<String, Object> json) throws ParseException {
        if (!KEY_TYPE.getValue().equals(JSONObjectUtils.getString(json, "kty"))) {
            throw new ParseException("The key type kty must be " + KEY_TYPE.getValue(), 0);
        }
        JWSAlgorithm alg = JWSAlgorithm.parse(JSONObjectUtils.getString(json, "alg"));
        Base64URL pub = JSONObjectUtils.getBase64URL(json, PUBLIC_KEY_PARAMETER);
        if (pub == null) {
            throw new ParseException("Missing public key \"" + PUBLIC_KEY_PARAMETER + "\" parameter", 0);
        }
        Base64URL priv = JSONObjectUtils.getBase64URL(json, PRIVATE_KEY_PARAMETER);
        try {
            return new CompositeMLDSAKey(alg, pub.decode(), priv == null ? null : priv.decode(),
                    JWKMetadata.parseKeyUse(json),
                    JWKMetadata.parseKeyOperations(json),
                    JSONObjectUtils.getString(json, "kid"),
                    JSONObjectUtils.getURI(json, "x5u"),
                    JSONObjectUtils.getBase64URL(json, "x5t"),
                    JSONObjectUtils.getBase64URL(json, "x5t#S256"),
                    JWKMetadata.parseX509CertChain(json),
                    JSONObjectUtils.getEpochSecondAsDate(json, "exp"),
                    JSONObjectUtils.getEpochSecondAsDate(json, "nbf"),
                    JSONObjectUtils.getEpochSecondAsDate(json, "iat"),
                    JWKMetadata.parseKeyRevocation(json));
        } catch (IllegalArgumentException e) {
            throw new ParseException(e.getMessage(), 0);
        }
    }

     /** The composite JWS algorithm for a LAMPS composite OID, {@code null} if not one. */
    static JWSAlgorithm algorithmFromOid(final String oid) {
        for (Map.Entry<JWSAlgorithm, String> e : OIDS.entrySet()) {
            if (e.getValue().equals(oid)) return e.getKey();
        }
        return null;
    }

    /** True if the JCA public key is a supported composite (by its SPKI OID). */
    static boolean isCompositePublicKey(final PublicKey publicKey) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
            return algorithmFromOid(spki.getAlgorithm().getAlgorithm().getId()) != null;
        } catch (RuntimeException e) {

                return false;   // no or unparseable encoding: not ours
        }
    }

    /**
     * From JCA composite keys (e.g. a PEM parsed by BouncyCastle): unwraps the raw
     * pub / priv octets from SubjectPublicKeyInfo / PKCS#8, the inverse of
     * toPublicKey() / toPrivateKey().
     *
     * @param privateKey {@code null} for a public JWK.
     */
    public static CompositeMLDSAKey fromJCA(final PublicKey publicKey,
                                            final PrivateKey privateKey) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        JWSAlgorithm alg = algorithmFromOid(spki.getAlgorithm().getAlgorithm().getId());
        if (alg == null) {
            throw new IllegalArgumentException("Not a composite ML-DSA public key");
        }
        byte[] priv = null;
        if (privateKey != null) {
            PrivateKeyInfo pki = PrivateKeyInfo.getInstance(privateKey.getEncoded());
            String privOid = pki.getPrivateKeyAlgorithm().getAlgorithm().getId();
            if (!alg.equals(algorithmFromOid(privOid))) {
                throw new IllegalArgumentException("Composite public/private algorithm mismatch");
            }
            priv = pki.getPrivateKey().getOctets();
        }
        return new CompositeMLDSAKey(alg, spki.getPublicKeyData().getBytes(), priv,
                null, null, null, null, null, null, null, null, null, null, null);
    }

     /** As {@link #fromJCA(PublicKey, PrivateKey)}, with a key ID. */
    public static CompositeMLDSAKey fromJCA(final PublicKey publicKey, final PrivateKey privateKey,
                                            final String kid) {
        CompositeMLDSAKey k = fromJCA(publicKey, privateKey);
        return new CompositeMLDSAKey((JWSAlgorithm) k.getAlgorithm(), k.publicData, k.privateData,
                null, null, kid, null, null, null, null, null, null, null, null);
    }


    private CompositeMLDSAKey copy(final byte[] priv, final KeyRevocation revocation) {
        return new CompositeMLDSAKey((JWSAlgorithm) getAlgorithm(), publicData, priv,
                getKeyUse(), getKeyOperations(), getKeyID(), getX509CertURL(),
                getX509CertThumbprint(), getX509CertSHA256Thumbprint(), getX509CertChain(),
                getExpirationTime(), getNotBeforeTime(), getIssueTime(), revocation);
    }

    @Override
    protected Base64URL encodedPublicData() {
        return Base64URL.encode(publicData);
    }

    @Override
    protected Base64URL encodedPrivateData() {
        return privateData == null ? null : Base64URL.encode(privateData);
    }

    @Override
    public boolean isPrivate() {
        return privateData != null;
    }

    @Override
    public CompositeMLDSAKey toPublicJWK() {
        return copy(null, getKeyRevocation());
    }

    @Override
    public CompositeMLDSAKey toRevokedJWK(final KeyRevocation keyRevocation) {
        if (getKeyRevocation() != null) {
            throw new IllegalStateException("Already revoked");
        }
        return copy(privateData, Objects.requireNonNull(keyRevocation, "keyRevocation"));
    }

    /** Size of the encoded composite public key, in bits. */
    @Override
    public int size() {
        return publicData.length * 8;
    }

    private AlgorithmIdentifier algorithmIdentifier() {
        String oid = OIDS.get((JWSAlgorithm) getAlgorithm());
        return new AlgorithmIdentifier(new ASN1ObjectIdentifier(oid));
    }

    @Override
    public PublicKey toPublicKey() throws JOSEException {
        try {
            byte[] spki = new SubjectPublicKeyInfo(algorithmIdentifier(), publicData).getEncoded();
            return KeyFactory.getInstance("COMPOSITE", BouncyCastleProviderSingleton.getInstance())
                    .generatePublic(new X509EncodedKeySpec(spki));
        } catch (Exception e) {
            throw new JOSEException("Invalid composite public key: " + e.getMessage(), e);
        }
    }

    @Override
    public PrivateKey toPrivateKey() throws JOSEException {
        if (privateData == null) {
            return null;
        }
        try {
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new ASN1Integer(0));
            v.add(algorithmIdentifier());
            v.add(new DEROctetString(privateData));
            byte[] pkcs8 = new DERSequence(v).getEncoded();
            return KeyFactory.getInstance("COMPOSITE", BouncyCastleProviderSingleton.getInstance())
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception e) {
            throw new JOSEException("Invalid composite private key: " + e.getMessage(), e);
        }
    }

    @Override
    public KeyPair toKeyPair() throws JOSEException {
        return new KeyPair(toPublicKey(), toPrivateKey());
    }

    /** X.509 certificates for composite keys are not supported in this PoC. */
    @Override
    public boolean matches(final X509Certificate cert) {
        return false;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (!(o instanceof CompositeMLDSAKey) || !super.equals(o)) return false;
        CompositeMLDSAKey that = (CompositeMLDSAKey) o;
        return Arrays.equals(publicData, that.publicData)
                && Arrays.equals(privateData, that.privateData);
    }

    @Override
    public int hashCode() {
        int h = 31 * super.hashCode() + Arrays.hashCode(publicData);
        return 31 * h + Arrays.hashCode(privateData);
    }
}
