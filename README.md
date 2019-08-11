# Kafka X509 Config Provider

Kafka by default supports only TLS certificates and keys in the Java KeyStore format (JKS).
This is often inconvenient in environments such as Kubernetes, which work by default with X509 and PEM certificates.
This project provides Kafka ConfigProvider implementations which are able to load the certificates and keys from the X509 / PEM files into JKS files in temporary directory and use them in Kafka clients or brokers.
