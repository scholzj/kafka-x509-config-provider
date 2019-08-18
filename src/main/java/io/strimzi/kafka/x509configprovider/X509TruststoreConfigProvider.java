package io.strimzi.kafka.x509configprovider;

import org.apache.kafka.common.config.ConfigChangeCallback;
import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class X509TruststoreConfigProvider implements ConfigProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(X509TruststoreConfigProvider.class);

    private final CertificateFactory factory;

    public X509TruststoreConfigProvider() {
        LOGGER.warn("Constructor called");
        factory = certificateFactory();
    }

    @Override
    public ConfigData get(String path) {
        LOGGER.warn("Get called with path={}" , path);

        //return setupTrustStore().getAbsolutePath();

        return null;
    }

    @Override
    public ConfigData get(String path, Set<String> keys) {
        LOGGER.warn("Get called with path={} and keys={}" , path, keys);

        if (path == null || path.isEmpty()) {
            path = keys.iterator().next();
        }

        String trustStorePath = setupTrustStore("changeit".toCharArray(), x509Certificate(path)).getAbsolutePath();

        Map<String, String> data = new HashMap<>();
        //data.put("xxx", "AAA");
        for (String key : keys) {
            LOGGER.warn("Return values {}={}" , key, trustStorePath);
            data.put(key, trustStorePath);
        }

        return new ConfigData(data);
        //return
    }

    @Override
    public void subscribe(String path, Set<String> keys, ConfigChangeCallback callback) {
        LOGGER.warn("Subscribe called with path={} and keys={} and callback={}" , path, keys, callback);
        throw new UnsupportedOperationException();
    }

    @Override
    public void unsubscribe(String path, Set<String> keys, ConfigChangeCallback callback) {
        LOGGER.warn("Unsubscribe called with path={} and keys={} and callback={}" , path, keys, callback);

        throw new UnsupportedOperationException();
    }

    @Override
    public void unsubscribeAll() {
        LOGGER.warn("Unsubscribe all called");
        throw new UnsupportedOperationException();
    }

    @Override
    public void close() throws IOException {
        LOGGER.warn("Close called");
    }

    @Override
    public void configure(Map<String, ?> configs) {
        LOGGER.warn("Configure called");

        for (Map.Entry entry : configs.entrySet())  {
            LOGGER.warn("Config key {} with value {}", entry.getKey(), entry.getValue());
        }
    }

    private CertificateFactory certificateFactory() {
        CertificateFactory factory = null;
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException("No security provider with support for X.509 certificates", e);
        }
        return factory;
    }

    private X509Certificate x509Certificate(String certPath) {

        try {
            byte[] cert = Files.readAllBytes(Paths.get(certPath));

            Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(cert));
            if (certificate instanceof X509Certificate) {
                return (X509Certificate) certificate;
            } else {
                throw new RuntimeException("Not an X509Certificate: " + certificate);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read the file " + certPath, e);
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to load the certificate from file " + certPath, e);
        }
    }

    /*private X509Certificate x509Certificate(byte[] bytes) throws CertificateException {
        Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(bytes));
        if (certificate instanceof X509Certificate) {
            return (X509Certificate) certificate;
        } else {
            throw new CertificateException("Not an X509Certificate: " + certificate);
        }
    }*/

    private File setupTrustStore(char[] password, X509Certificate caCertCO) {
        try {
            KeyStore trustStore = null;
            trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, password);
            trustStore.setEntry(caCertCO.getSubjectDN().getName(), new KeyStore.TrustedCertificateEntry(caCertCO), null);
            return store(password, trustStore);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private File store(char[] password, KeyStore trustStore) throws Exception {
        File f = null;
        try {
            f = File.createTempFile(getClass().getName(), "ts");
            f.deleteOnExit();
            try (OutputStream os = new BufferedOutputStream(new FileOutputStream(f))) {
                trustStore.store(os, password);
            }
            return f;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException | RuntimeException e) {
            if (f != null && !f.delete()) {
                LOGGER.warn("Failed to delete temporary file in exception handler");
            }
            throw e;
        }
    }
}
