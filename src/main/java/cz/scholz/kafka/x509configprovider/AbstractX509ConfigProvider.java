/*
 * Copyright Jakub Scholz
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package cz.scholz.kafka.x509configprovider;

import org.apache.kafka.common.KafkaException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
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
import java.util.HashSet;
import java.util.Set;

public class AbstractX509ConfigProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(AbstractX509ConfigProvider.class);

    protected static final String PASSWORD = "";

    protected final CertificateFactory factory;

    public AbstractX509ConfigProvider() {
        this.factory = certificateFactory();
    }

    private CertificateFactory certificateFactory() {
        CertificateFactory factory;

        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            LOGGER.error("No security provider with support for X.509 certificates", e);
            throw new KafkaException("No security provider with support for X.509 certificates", e);
        }

        return factory;
    }

    protected File store(char[] password, KeyStore keyStore) throws Exception {
        File f = null;
        try {
            f = File.createTempFile(getClass().getName(), ".p12");
            f.deleteOnExit();

            try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(f.toPath()))) {
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

    protected Set<Certificate> certificates(Set<String> certificatePaths) {
        Set<Certificate> certificates = new HashSet<>();

        for (String certPath : certificatePaths) {
            try {
                byte[] cert = Files.readAllBytes(Paths.get(certPath));
                certificates.addAll(factory.generateCertificates(new ByteArrayInputStream(cert)));
            } catch (IOException e) {
                throw new KafkaException("Failed to read the file " + certPath, e);
            } catch (CertificateException e) {
                throw new KafkaException("Failed to load the certificate from file " + certPath, e);
            }
        }

        return certificates;
    }
}
