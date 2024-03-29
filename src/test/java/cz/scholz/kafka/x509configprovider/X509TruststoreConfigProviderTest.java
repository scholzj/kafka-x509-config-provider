/*
 * Copyright Jakub Scholz
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package cz.scholz.kafka.x509configprovider;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigData;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class X509TruststoreConfigProviderTest {
    private static final X509TruststoreConfigProvider TRUSTSTORE_PROVIDER = new X509TruststoreConfigProvider();

    @Test
    public void testLoadingOfOneCertificate() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String certPath = Objects.requireNonNull(getClass().getResource("/key.crt")).getPath();
        ConfigData data = TRUSTSTORE_PROVIDER.get(certPath);

        assertThat(data.data().get(certPath), is(notNullValue()));

        String truststorePath = data.data().get(certPath);
        KeyStore store = KeyStore.getInstance("pkcs12");
        store.load(Files.newInputStream(Paths.get(truststorePath)), AbstractX509ConfigProvider.PASSWORD.toCharArray());

        Enumeration<String> aliases = store.aliases();
        int noOfCerts = 0;

        while (aliases.hasMoreElements())   {
            noOfCerts++;
            String alias = aliases.nextElement();
            Certificate cert = store.getCertificate(alias);
            X509Certificate x509Cert = (X509Certificate) cert;
            assertThat(x509Cert.getSubjectDN().getName(), is("CN=Internal, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ"));
        }

        assertThat(noOfCerts, is(1));
    }

    @Test
    public void testLoadCa() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String certPath = Objects.requireNonNull(getClass().getResource("/ca.crt")).getPath();
        ConfigData data = TRUSTSTORE_PROVIDER.get(certPath);

        assertThat(data.data().get(certPath), is(notNullValue()));

        String truststorePath = data.data().get(certPath);
        KeyStore store = KeyStore.getInstance("pkcs12");
        store.load(Files.newInputStream(Paths.get(truststorePath)), AbstractX509ConfigProvider.PASSWORD.toCharArray());

        Enumeration<String> aliases = store.aliases();
        int noOfCerts = 0;

        while (aliases.hasMoreElements())   {
            noOfCerts++;
            String alias = aliases.nextElement();
            Certificate cert = store.getCertificate(alias);
            X509Certificate x509Cert = (X509Certificate) cert;
            assertThat(x509Cert.getSubjectDN().getName(), is("CN=RootCA, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ"));
        }

        assertThat(noOfCerts, is(1));
    }

    @Test
    public void testLoadBundle() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String certPath = Objects.requireNonNull(getClass().getResource("/key-bundle.crt")).getPath();
        ConfigData data = TRUSTSTORE_PROVIDER.get(certPath);

        assertThat(data.data().get(certPath), is(notNullValue()));

        String truststorePath = data.data().get(certPath);
        KeyStore store = KeyStore.getInstance("pkcs12");
        store.load(Files.newInputStream(Paths.get(truststorePath)), AbstractX509ConfigProvider.PASSWORD.toCharArray());

        Enumeration<String> aliases = store.aliases();
        int noOfCerts = 0;

        while (aliases.hasMoreElements())   {
            noOfCerts++;
            String alias = aliases.nextElement();
            Certificate cert = store.getCertificate(alias);
            X509Certificate x509Cert = (X509Certificate) cert;
            assertThat(x509Cert.getSubjectDN().getName(), anyOf(
                    is("CN=Internal, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ"),
                    is("CN=IntermediateCA, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ")
            ));
        }

        assertThat(noOfCerts, is(2));
    }

    @Test
    public void testLoadMultipleCerts() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        String certPath = Objects.requireNonNull(getClass().getResource("/key.crt")).getPath();
        Set<String> moreCertPaths = new HashSet<>();
        moreCertPaths.add(Objects.requireNonNull(getClass().getResource("/ca.crt")).getPath());
        moreCertPaths.add(Objects.requireNonNull(getClass().getResource("/key2.crt")).getPath());
        ConfigData data = TRUSTSTORE_PROVIDER.get(certPath, moreCertPaths);

        assertThat(data.data().get(certPath), is(notNullValue()));
        assertThat(data.data().get(Objects.requireNonNull(getClass().getResource("/ca.crt")).getPath()), is(notNullValue()));
        assertThat(data.data().get(Objects.requireNonNull(getClass().getResource("/key2.crt")).getPath()), is(notNullValue()));

        String truststorePath = data.data().get(certPath);
        KeyStore store = KeyStore.getInstance("pkcs12");
        store.load(Files.newInputStream(Paths.get(truststorePath)), AbstractX509ConfigProvider.PASSWORD.toCharArray());

        Enumeration<String> aliases = store.aliases();
        int noOfCerts = 0;

        while (aliases.hasMoreElements())   {
            noOfCerts++;
            String alias = aliases.nextElement();
            Certificate cert = store.getCertificate(alias);
            X509Certificate x509Cert = (X509Certificate) cert;
            assertThat(x509Cert.getSubjectDN().getName(), anyOf(
                    is("CN=RootCA, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ"),
                    is("CN=Internal, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ"),
                    is("CN=External, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ")
            ));
        }

        assertThat(noOfCerts, is(3));
    }

    @Test
    public void testLoadNoCerts() {
        ConfigData data = TRUSTSTORE_PROVIDER.get(null);
        assertThat(data.data().size(), is(0));
    }

    @Test
    public void testLoadInvalidCert() {
        KafkaException e = assertThrows(KafkaException.class, () -> TRUSTSTORE_PROVIDER.get(Objects.requireNonNull(getClass().getResource("/dummy.txt")).getPath()));
        assertThat(e.getMessage(), containsString("Failed to load the certificate from file"));
    }
}
