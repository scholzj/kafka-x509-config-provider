package io.strimzi.kafka.x509configprovider;

import org.apache.kafka.common.KafkaException;
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
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public class X509TruststoreConfigProvider implements ConfigProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(X509TruststoreConfigProvider.class);

    private static final String PASSWORD = "changeit";

    private final CertificateFactory factory;

    public X509TruststoreConfigProvider() {
        LOGGER.warn("Constructor called");
        factory = certificateFactory();
    }

    @Override
    public ConfigData get(String path) {
        LOGGER.warn("Get called with path={}" , path);

        Set<String> certificatePaths = new HashSet<>();

        if (path != null && !path.isEmpty()) {
            certificatePaths.add(path);
        }

        return getTrustStoreConfig(certificatePaths);
    }

    @Override
    public ConfigData get(String path, Set<String> keys) {
        LOGGER.warn("Get called with path={} and keys={}" , path, keys);

        Set<String> certificatePaths = new HashSet<>();
        certificatePaths.addAll(keys);

        if (path != null && !path.isEmpty()) {
            certificatePaths.add(path);
        }

        return getTrustStoreConfig(certificatePaths);
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

    private ConfigData getTrustStoreConfig(Set<String> certificatePaths)    {
        String trustStorePath = setupTrustStore(PASSWORD.toCharArray(), x509Certificate(certificatePaths)).getAbsolutePath();

        Map<String, String> data = new HashMap<>();
        for (String key : certificatePaths) {
            LOGGER.warn("Return values {}={}" , key, trustStorePath);
            data.put(key, trustStorePath);
        }

        return new ConfigData(data);
    }

    private CertificateFactory certificateFactory() {
        CertificateFactory factory;

        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new KafkaException("No security provider with support for X.509 certificates", e);
        }

        return factory;
    }

    private Set<X509Certificate> x509Certificate(Set<String> certificatePaths) {
        Set<X509Certificate> certificates = new HashSet<>();

        for (String certPath : certificatePaths) {
            try {
                byte[] cert = Files.readAllBytes(Paths.get(certPath));

                Certificate certificate = factory.generateCertificate(new ByteArrayInputStream(cert));
                if (certificate instanceof X509Certificate) {
                    certificates.add((X509Certificate) certificate);
                } else {
                    throw new KafkaException("Not an X509Certificate: " + certificate);
                }
            } catch (IOException e) {
                throw new KafkaException("Failed to read the file " + certPath, e);
            } catch (CertificateException e) {
                throw new KafkaException("Failed to load the certificate from file " + certPath, e);
            }
        }

        return certificates;
    }

    private File setupTrustStore(char[] password, Set<X509Certificate> certs) {
        try {
            KeyStore trustStore = null;
            trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, password);

            for (X509Certificate cert : certs) {
                trustStore.setEntry(cert.getSubjectDN().getName(), new KeyStore.TrustedCertificateEntry(cert), null);
            }

            return store(password, trustStore);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private File store(char[] password, KeyStore keyStore) throws Exception {
        File f = null;
        try {
            f = File.createTempFile(getClass().getName(), "ts");
            f.deleteOnExit();

            try (OutputStream os = new BufferedOutputStream(new FileOutputStream(f))) {
                keyStore.store(os, password);
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
