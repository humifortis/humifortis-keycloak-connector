package tech.humifortis.keycloak.client;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Collection;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * The client certificate and the private CA of the connector, read from PEM files: what an operator already has, with no keystore
 * to build. The key is PKCS#8 ("BEGIN PRIVATE KEY"; {@code openssl pkcs8 -topk8 -nocrypt} converts the older forms).
 */
final class PemKeys {
    private static final char[] NO_PASSWORD = new char[0];

    private PemKeys() {}

    static KeyManager[] keyManagers(String certFile, String keyFile) throws Exception {
        Certificate[] chain = certificates(certFile);
        if (chain.length == 0) throw new IllegalStateException("no certificate in " + certFile);
        PrivateKey key = privateKey(Files.readString(Path.of(keyFile)));
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("connector", key, NO_PASSWORD, chain);
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, NO_PASSWORD);
        return factory.getKeyManagers();
    }

    static TrustManager[] trustManagers(String caFile) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        int i = 0;
        for (Certificate c : certificates(caFile)) store.setCertificateEntry("ca-" + i++, c);
        if (i == 0) throw new IllegalStateException("no certificate in " + caFile);
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        return factory.getTrustManagers();
    }

    private static Certificate[] certificates(String file) throws Exception {
        try (InputStream in = Files.newInputStream(Path.of(file))) {
            Collection<? extends Certificate> all = CertificateFactory.getInstance("X.509").generateCertificates(in);
            return all.toArray(new Certificate[0]);
        }
    }

    static PrivateKey privateKey(String pem) throws Exception {
        if (pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN EC PRIVATE KEY")) {
            throw new IllegalStateException("the key must be PKCS#8 (BEGIN PRIVATE KEY): openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.pk8.pem");
        }
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        Exception last = null;
        for (String algorithm : new String[] {"RSA", "EC", "Ed25519"}) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
            } catch (Exception e) {
                last = e;
            }
        }
        throw new IllegalStateException("unsupported private key", last);
    }
}
