# JBang Catalog

Scripts:
- HTTP Server 
- TLS client (like openssl s_client)

[Download JBang](https://www.jbang.dev/download).

## HTTP Server

Serve local files using (JDK HTTP Server).

- Run: `jbang http-server@sansnom`
- Usage/help: `jbang http-server@sansnom -h`

Alternatives:
- `jbang org.javastack:httpd:1.1.2 8787 .` using [ggrandes/httpd](https://github.com/ggrandes/httpd).
- [JEP-408](https://openjdk.java.net/jeps/408) coming soon ?

## TLS client

Check TLS connection to server (you can choose protocol, ciphers) and build a truststore if necessary.

- Run: `jbang tls-client@sansnom -connect www.google.fr:443`
- Usage/help: `jbang tls-client@sansnom -h`

Alternatives:
- `openssl s_client`
- Original `InstallCert.java`