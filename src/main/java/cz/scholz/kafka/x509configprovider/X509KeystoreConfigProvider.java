/*
 * Copyright Jakub Scholz
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package cz.scholz.kafka.x509configprovider;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigChangeCallback;
import org.apache.kafka.common.config.ConfigData;
import org.apache.kafka.common.config.provider.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class X509KeystoreConfigProvider extends AbstractX509ConfigProvider implements ConfigProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(X509KeystoreConfigProvider.class);

    public X509KeystoreConfigProvider() {
        super();
    }

    ////////////////////
    // Interface
    ////////////////////

    @Override
    public ConfigData get(String path) {
        return null;
    }

    @Override
    public ConfigData get(String path, Set<String> keys) {
        return null;
    }

    @Override
    public void close() {
        LOGGER.info("Closing X509KeystoreConfigProvider");
    }

    @Override
    public void configure(Map<String, ?> configs) {
        LOGGER.info("Configuring X509KeystoreConfigProvider: {}", configs);
    }

    ////////////////////
    // Implementation
    ////////////////////

    private ConfigData getKeyStoreConfig(String certPath, String keyPath)    {
        LOGGER.info("Generating keystore with public key {} and private key {}", certPath, keyPath);



        String keyStorePath = setupKeystoreStore(PASSWORD.toCharArray(), keyPath, certPath).getAbsolutePath();

        Map<String, String> data = new HashMap<>();
        data.put(keyPath, keyStorePath);

        LOGGER.info("New keystore {} is ready", keyStorePath);

        return new ConfigData(data);
    }

    private File setupKeystoreStore(char[] password, String keyPath, String certPath) {
        try {
            Set<String> certPaths = new HashSet<>();
            certPaths.add(certPath);

            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(null, null);
            keystore.setKeyEntry("private-key", loadRSAPrivateKey(keyPath), new char[0], certificates(certPaths).toArray(new Certificate[0]));

            return store(password, keystore);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PrivateKey loadRSAPrivateKey(String keyPath) {
        try {
            byte[] key = Files.readAllBytes(Paths.get(keyPath));
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(key));
        } catch (IOException e) {
            throw new KafkaException("Failed to read the file " + keyPath, e);
        } catch (InvalidKeySpecException e) {
            throw new KafkaException("Failed to load the private key from file " + keyPath, e);
        } catch (NoSuchAlgorithmException e) {
            throw new KafkaException("KeyFactory implementing algorithm RSA was not found", e);
        }
    }
}
