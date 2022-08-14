/*
 * Copyright Jakub Scholz
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package cz.scholz.kafka.x509configprovider;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class X509TruststoreConfigProvider extends AbstractX509ConfigProvider implements ConfigProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(X509TruststoreConfigProvider.class);

    public X509TruststoreConfigProvider() {
        super();
    }

    ////////////////////
    // Interface
    ////////////////////

    @Override
    public ConfigData get(String path) {
        Set<String> certificatePaths = new HashSet<>();

        if (path != null && !path.isEmpty()) {
            certificatePaths.add(path);
        }

        return getTrustStoreConfig(certificatePaths);
    }

    @Override
    public ConfigData get(String path, Set<String> keys) {
        Set<String> certificatePaths = new HashSet<>(keys);

        if (path != null && !path.isEmpty()) {
            certificatePaths.add(path);
        }

        return getTrustStoreConfig(certificatePaths);
    }

    @Override
    public void close() {
        LOGGER.info("Closing X509TruststoreConfigProvider");
    }

    @Override
    public void configure(Map<String, ?> configs) {
        LOGGER.info("Configuring X509TruststoreConfigProvider: {}", configs);
    }

    ////////////////////
    // Implementation
    ////////////////////

    private ConfigData getTrustStoreConfig(Set<String> certificatePaths)    {
        LOGGER.info("Generating truststore with certificates {}", certificatePaths);

        String trustStorePath = setupTrustStore(PASSWORD.toCharArray(), certificates(certificatePaths)).getAbsolutePath();

        Map<String, String> data = new HashMap<>();
        for (String key : certificatePaths) {
            LOGGER.warn("Return values {}={}" , key, trustStorePath);
            data.put(key, trustStorePath);
        }

        LOGGER.info("New truststore {} is ready", trustStorePath);

        return new ConfigData(data);
    }

    private File setupTrustStore(char[] password, Set<Certificate> certificates) {
        try {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, null);

            int i = 0;

            for (Certificate cert : certificates) {
                trustStore.setEntry("trusted-" + i++, new KeyStore.TrustedCertificateEntry(cert), null);
            }

            return store(password, trustStore);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
