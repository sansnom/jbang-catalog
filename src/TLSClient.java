///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.5.0
/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.Callable;

import javax.net.ssl.*;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/**
 * TLS client like openssl s_client also allows to build a truststore.
 *
 * Original code by Andreas Sterbenz from: http://blogs.sun.com/andreas/resource/InstallCert.java
 */
@Command(name = "tls-client",
	description = {
		"Check TLS configuration for a given server (allow to build a truststore)",
		"Example: jbang tls-client@sansnom -connect www.google.fr"
	},
	usageHelpWidth = 160,
	mixinStandardHelpOptions = true)
public class TLSClient implements Callable<Integer> {

	private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

	@Option(names = {"-connect"}, description = "HOST(:PORT) default port is 443", required = true)
	private String connect;

	@Option(names = {"-p", "--pass"}, description = "password for keystore (default ${DEFAULT-VALUE})", defaultValue = "changeit")
	private String passphrase;

	@Option(names = {"-a", "--all"}, description = "Accept all algorithm (default ${DEFAULT-VALUE})", defaultValue = "false")
	private boolean acceptAll;

	@Option(names = {"-t", "--truststore"}, description = "trust store path (default is Java)")
	private File trustStorePath;

	@Option(names = {"-cipher"}, description = "cipher suite to be used", split = ",")
	private String[] cipher;

	@Option(names = {"-tls1"}, description = "Just use TLSv1")
	private boolean tls1;

	@Option(names = {"-tls1_1"}, description = "Just use TLSv1.1")
	private boolean tls11;

	@Option(names = {"-tls1_2"}, description = "Just use TLSv1.2")
	private boolean tls12;

	@Option(names = {"-tls1_3"}, description = "Just use TLSv1.3")
	private boolean tls13;

	@Option(names = {"-servername"}, description = "Set TLS extension servername (SNI) in ClientHello (default)")
	private String serverName;

	@Option(names = {"-o", "--out"}, description = "build trust store")
	private boolean buildTrustStore;

	public static void main(String[] args) {
		System.out.println(String.join(" ",args));
		CommandLine commandLine = new CommandLine(new TLSClient());
		int exitCode = commandLine.execute(args);
		System.exit(exitCode);
	}

	@Override
	public Integer call() {
		try {
			String[] split = connect.split(":");
			String host = split[0];
			int port = 443;
			if (split.length == 2) {
				port = Integer.parseInt(split[1]);
			}
			System.out.println();

			String disabledAlgorithms = Security.getProperty("jdk.tls.disabledAlgorithms");
			System.out.println("jdk.tls.disabledAlgorithms: " + disabledAlgorithms);

			String legacyAlgorithms = Security.getProperty("jdk.tls.legacyAlgorithms");
			System.out.println("jdk.tls.legacyAlgorithms: " + legacyAlgorithms);

			String certpathDisabledAlgorithms = Security.getProperty("jdk.certpath.disabledAlgorithms");
			System.out.println("jdk.certpath.disabledAlgorithms: " + certpathDisabledAlgorithms);
			if (this.acceptAll) {
				Security.setProperty("jdk.tls.disabledAlgorithms", "");
				Security.setProperty("jdk.tls.legacyAlgorithms", "");
				Security.setProperty("jdk.certpath.disabledAlgorithms", "");
			}

			File trustStoreFile = getTrustStoreFile();
			System.out.printf("keystore : [%s]%n", trustStoreFile.getAbsolutePath());
			KeyStore ks = loadKeyStore(passphrase.toCharArray(), trustStoreFile);

			SSLContext context = SSLContext.getInstance("TLS");

			TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
			tmf.init(ks);
			X509TrustManager defaultTrustManager = (X509TrustManager)tmf.getTrustManagers()[0];
			SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
			context.init(null, new TrustManager[] {tm}, null);

			SSLSocketFactory factory = context.getSocketFactory();

			System.out.println();
			System.out.printf("Opening connection to %s:%d%n", host, port);

			// XXX handle proxy using factory.createSocket(socket, host, port)
			try (SSLSocket socket = (SSLSocket)factory.createSocket(host, port)) {
				socket.setSoTimeout(10000);

				SSLParameters sslParameters = socket.getSSLParameters();
				if (cipher != null && cipher.length > 0) {
					sslParameters.setCipherSuites(cipher);
				}

				String[] protocol = getProtocol();
				if (protocol != null) {
					sslParameters.setProtocols(protocol);
				}

				if (serverName != null) {
					SNIServerName sniServerName = new SNIHostName(serverName);
					sslParameters.setServerNames(Collections.singletonList(sniServerName));
				}

				System.out.println("Starting SSL handshake...");
				socket.startHandshake();
				SSLSession session = socket.getSession();

				System.out.println("SSL handshake DONE.");
				System.out.println();
				System.out.println("protocol: " + session.getProtocol());
				System.out.println("cipher  : " + session.getCipherSuite());

				try {
					defaultTrustManager.checkServerTrusted(tm.chain, tm.authType);
					System.out.println("Server is trusted.");
				} catch (final Exception e) {
					System.out.printf("Server is NOT TRUSTED (%s).%n", e.getMessage());
				}
			} catch (SSLException e) {
				e.printStackTrace(System.out);
			}

			X509Certificate[] chain = tm.chain;
			if (chain == null) {
				System.out.println("Could not obtain server certificate chain");
				return -1;
			}

			System.out.println();
			System.out.printf("Server sent %d certificate(s):", chain.length);
			System.out.println();
			MessageDigest sha1 = MessageDigest.getInstance("SHA1");
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			for (int i = 0; i < chain.length; i++) {
				X509Certificate cert = chain[i];
				System.out.printf(" %d Subject %s%n", (i + 1), cert.getSubjectX500Principal().getName());
				System.out.printf("   SAN     %s%n", cert.getSubjectAlternativeNames());
				System.out.printf("   Issuer  %s%n", cert.getIssuerX500Principal().getName());
				System.out.printf("   sha1    %s%n", certDigest(sha1, cert));
				System.out.printf("   md5     %s%n", certDigest(md5, cert));
				System.out.println();
			}

			X509Certificate cert = chain[0];
			Map<String, String> dn = this.splitDN(cert);
			if (dn.containsKey("CN")) {
				String commonName = dn.get("CN");
				if (!commonName.equalsIgnoreCase(host)) {
					System.out.printf("*** CN [%s] is not equal to host [%s] (check subject alternative name)%n", commonName, host);
				}
				// TODO check SAN
			}

			if (this.buildTrustStore) {
				addToKeyStore(host, passphrase.toCharArray(), ks, chain);
			}

			return 0;
		} catch (Exception e) {
			e.printStackTrace(System.out);
			return -2;
		}
	}

	private String[] getProtocol() {
		if (this.tls1) {
			return new String[]{"TLSv1"};
		} else if (this.tls11) {
			return new String[]{"TLSv1.1"};
		} else if (this.tls12) {
			return new String[]{"TLSv1.2"};
		} else if (this.tls13) {
			return new String[]{"TLSv1.3"};
		}
		return null;
	}

	// sun.security.x509.X500Name is not exported (otherwise could have used it)
	private Map<String, String> splitDN(X509Certificate cert) {
		String name = cert.getSubjectX500Principal().getName();
		String[] values = name.split(",");
		Map<String, String> result = new HashMap<>();
		for (String value : values) {
			int indexOf = value.indexOf("=");
			result.put(value.substring(0, indexOf), value.substring(indexOf + 1));
		}
		return result;
	}

	private String certDigest(MessageDigest messageDigest, X509Certificate cert) throws CertificateEncodingException {
		messageDigest.update(cert.getEncoded());
		return toHexString(messageDigest.digest());
	}

	private File getTrustStoreFile() {
		if (this.trustStorePath != null) {
			return this.trustStorePath;
		}
		char separatorChar = File.separatorChar;
		File dir = new File(System.getProperty("java.home") + separatorChar + "lib" + separatorChar + "security");
		return new File(dir, "cacerts");
	}

	private static void addToKeyStore(String host, char[] passphrase, KeyStore ks, X509Certificate[] chain) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		System.out.printf("Choose which certificate you want to add ? [1,%d]%n", chain.length);
		Scanner in = new Scanner(System.in);
		int k = in.nextInt();

		X509Certificate cert = chain[k];
		String alias = host + "-" + (k + 1);
		ks.setCertificateEntry(alias, cert);

		try (OutputStream out = new FileOutputStream("jssecacerts")) {
			ks.store(out, passphrase);
		}

		System.out.println();
		System.out.println(cert);
		System.out.println();
		System.out.println("Added certificate to keystore 'jssecacerts' using alias '" + alias + "'");
	}

	private static KeyStore loadKeyStore(char[] passphrase, File file) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
		try (InputStream in = new FileInputStream(file)) {
			KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
			ks.load(in, passphrase);
			return ks;
		}
	}

	private static String toHexString(byte[] bytes) {
		StringBuilder sb = new StringBuilder(bytes.length * 3);
		for (int b : bytes) {
			b &= 0xff;
			sb.append(HEX_DIGITS[b >> 4]);
			sb.append(HEX_DIGITS[b & 15]);
			sb.append(' ');
		}
		return sb.toString();
	}

	private static class SavingTrustManager implements X509TrustManager {

		private final X509TrustManager tm;
		private X509Certificate[] chain;
		private String authType;

		SavingTrustManager(X509TrustManager tm) {
			this.tm = tm;
		}

		public X509Certificate[] getAcceptedIssuers() {
			return this.tm.getAcceptedIssuers();
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			this.tm.checkClientTrusted(chain, authType);
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType) {
			this.chain = chain;
			this.authType = authType;
		}
	}
}
