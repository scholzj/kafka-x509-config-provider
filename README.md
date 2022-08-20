# KeyStore and TrustStore Configuration Providers for Apache Kafka

`X509KeystoreConfigProvider` and `X509TruststoreConfigProvider` are [Apache Kafka®](https://kafka.apache.org) configuration providers which can be used to generate a PKCS12 keystore or truststore from PEM files with 509 certificates _on the fly_.
The PKCS12 files will be generated in a temporary directory and the path to them will be passed to Kafka as the output from the provider.
The providers currently supports unencrypted RSA Private keys and public keys.
They are passed to the provider as file paths.
The certificate files should be in the text format with the markers and look like this:

_Public key example_
```
-----BEGIN CERTIFICATE-----
...
...
...
-----END CERTIFICATE-----
```

_Private key example_
```
-----BEGIN PRIVATE KEY-----
...
...
...
-----END PRIVATE KEY-----
```

## Installation

You can download the archives with the binaries on GitHub release page.
You can download it, unpack it and copy the JAR file into the classpath of your Apache Kafka installation.
If you want to use it with Apache Kafka clients, you can also get the project directly from Maven repositories.

## Configuration

First, you need to initialize the providers:

```properties
config.providers=truststore,keystore
config.providers.keystore.class=cz.scholz.kafka.x509configprovider.X509KeystoreConfigProvider
config.providers.truststore.class=cz.scholz.kafka.x509configprovider.X509TruststoreConfigProvider
```

And then you can use them:

```properties
ssl.keystore.type=PKCS12
ssl.keystore.location=${keystore:/my-path-to-certs/user.key:/my-path-to-certs/user.crt}
ssl.keystore.password=
ssl.key.password=
ssl.truststore.type=PKCS12
ssl.truststore.location=${truststore:/my-path-to-certs/ca.crt}
ssl.truststore.password=
```

You should always configure the format to `PKCS12` and the passwords to empty strings.
When Kafka applies the configuration providers, you should see a configuration like this in the Kafka logs:

```
2022-08-20 15:41:30,575 INFO [echo-sink-connector|task-0] ConsumerConfig values:
    ssl.key.password = [hidden]
    ssl.keystore.location = /tmp/cz.scholz.kafka.x509configprovider.X509KeystoreConfigProvider18094880232725639415.p12
    ssl.keystore.password = [hidden]
    ssl.keystore.type = PKCS12
    ssl.truststore.location = /tmp/cz.scholz.kafka.x509configprovider.X509TruststoreConfigProvider7460901468812493428.p12
    ssl.truststore.password = [hidden]
    ssl.truststore.type = PKCS12
```

## Use cases

Apache Kafka can use PEM files directly.
So in most cases, you do not need to use this configuration provider, and you can use the PEM files directly.
But there are some use-cases when this is not possible.

When configuring Kafka Connect connectors, you often need to configure the TLS configuration not only for connecting to the Kafka brokers.
You usually need also to configure TLS for the connection to other system which your connector integrates with - from where it read the data or where it forwards the data from Apache Kafka.
This is typically done using some third party library which might not support using PEM files directly.
Sometimes, they support only the JKS or PKCS12 stores supported by Java by default.
In such case, you can use these config providers to create the keystore or truststore automatically 

Kafka Connect also allows you to override the configuration of the consumers or producers created for given connector.
Overriding the configs can be done in the connector configuration.
But when the underlying Connect cluster uses PKCS12 or JKS stores, it is not always easy to override the configuration from the connector with PEM files.
You can again use these configuration providers to dynamically create the PKCS12 stores and use them to override the default settings. 
