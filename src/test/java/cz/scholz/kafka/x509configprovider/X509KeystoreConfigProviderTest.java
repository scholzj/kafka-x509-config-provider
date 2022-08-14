/*
 * Copyright Jakub Scholz
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package cz.scholz.kafka.x509configprovider;

import org.apache.kafka.common.KafkaException;
import org.apache.kafka.common.config.ConfigData;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class X509KeystoreConfigProviderTest {
    private static X509KeystoreConfigProvider KEYSTORE_PROVIDER = new X509KeystoreConfigProvider();

    @Test
    public void testLoadPrivateKey() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        String keyPath = getClass().getResource("/key.pem").getPath();
        Set<String> certPaths = new HashSet<>();
        String certPath = getClass().getResource("/key.crt").getPath();
        certPaths.add(certPath);

        ConfigData data = KEYSTORE_PROVIDER.get(keyPath, certPaths);

        assertThat(data.data().size(), is(2));
        assertThat(data.data().get(keyPath), is(notNullValue()));
        assertThat(data.data().get(certPath), is(notNullValue()));

        String keystorePath = data.data().get(certPath);
        KeyStore store = KeyStore.getInstance("pkcs12");
        store.load(new FileInputStream(keystorePath), AbstractX509ConfigProvider.PASSWORD.toCharArray());

        Enumeration<String> aliases = store.aliases();
        int noOfKeys = 0;
        int noOfCerts = 0;

        while (aliases.hasMoreElements())   {
            noOfKeys++;
            String alias = aliases.nextElement();

            Key key = store.getKey(alias, null);
            assertThat(key, is(notNullValue()));

            Certificate[] certs = store.getCertificateChain(alias);

            for (Certificate cert : certs)  {
                noOfCerts++;
                X509Certificate x509Cert = (X509Certificate) cert;
                assertThat(x509Cert.getSubjectDN().getName(), is("CN=Internal, O=\"Jakub Scholz, Inc.\", L=Prague, C=CZ"));
            }


        }

        assertThat(noOfKeys, is(1));
        assertThat(noOfCerts, is(1));
    }
}
