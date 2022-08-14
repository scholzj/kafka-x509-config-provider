/*
 * Copyright Strimzi authors.
 * License: Apache License 2.0 (see the file LICENSE or http://apache.org/licenses/LICENSE-2.0.html).
 */
package cz.scholz.kafka.x509configprovider;

import org.apache.kafka.common.config.provider.ConfigProvider;
import org.junit.jupiter.api.Test;

import java.util.ServiceLoader;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class ServiceLoaderTest {
    @Test
    public void testServiceLoaderDiscovery() {
        ServiceLoader<ConfigProvider> serviceLoader = ServiceLoader.load(ConfigProvider.class);

        boolean keystoreProviderDiscovered = false;
        boolean truststoreProviderDiscovered = false;

        for (ConfigProvider service : serviceLoader)    {
            if (service instanceof X509TruststoreConfigProvider) {
                truststoreProviderDiscovered = true;
            } else if (service instanceof X509KeystoreConfigProvider) {
                keystoreProviderDiscovered = true;
            }
        }

        assertTrue(truststoreProviderDiscovered);
        assertTrue(keystoreProviderDiscovered);
    }
}
