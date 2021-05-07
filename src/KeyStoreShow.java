///usr/bin/env jbang "$0" "$@" ; exit $?
//DEPS info.picocli:picocli:4.5.0

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import picocli.CommandLine;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * Display keystore like keytool (but less verbose).
 *
 * Original code by Joshua Davies from: https://commandlinefanatic.com/cgi-bin/showarticle.cgi?article=art045
 */
public class KeyStoreShow implements Runnable {

	private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

	@Option(names = "--subject")
	private boolean showSubject = true;

	@Option(names = "--issue")
	private boolean showIssuer;

	@Option(names = "--start-date")
	private boolean showStartDate;

	@Option(names = "--end-date")
	private boolean showEndDate;

	@Option(names = "--public-key")
	private boolean showPubKey;

	@Option(names = "--fingerprint")
	private boolean showFingerprint = true;

	@Option(names = {"-p", "--password"})
	private String password;

	@Option(names = {"--type"})
	private String type;

	@Parameters
	private File keyStore;

	public static void main(String... args) {
		new CommandLine(new KeyStoreShow()).execute(args);
	}

	@Override
	public void run() {
		try {
			KeyStore ks = loadKeyStore();

			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				String alias = aliases.nextElement();
				System.out.print(alias + ": ");
				if (ks.isCertificateEntry(alias)) {
					System.out.println("Certificate Entry");
				} else {
					System.out.println("Private Key Entry");
				}
				Certificate cert = ks.getCertificate(alias);
				if (cert != null) {
					if ("X.509".equals(cert.getType())) {
						X509Certificate x509 = (X509Certificate)cert;
						if (showSubject) {
							System.out.println("Subject: " + x509.getSubjectX500Principal().toString());
						}
						if (showIssuer) {
							System.out.println("Issuer: " + x509.getIssuerX500Principal().toString());
						}
						if (showStartDate) {
							System.out.println("Start Date: " + x509.getNotBefore().toString());
						}
						if (showEndDate) {
							System.out.println("End Date: " + x509.getNotAfter().toString());
						}
						if (showPubKey) {
							PublicKey key = x509.getPublicKey();
							System.out.println(key.toString());
						}
						if (showFingerprint) {
							System.out.println("SHA256: " + getFingerPrint(x509));
						}
					} else {
						System.out.println("Unrecognized certificate type '" + cert.getType() + "'");
					}
				}
			}
		} catch (NoSuchAlgorithmException | CertificateException | KeyStoreException | IOException e) {
			e.printStackTrace();
		}
	}

	private static String getFingerPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] der = cert.getEncoded();
		md.update(der);
		byte[] digest = md.digest();
		String digestHex = toHexString(digest);
		return digestHex.toLowerCase();
	}

	private KeyStore loadKeyStore() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
		try (FileInputStream in = new FileInputStream(this.keyStore)) {
			ks.load(in, this.password == null ? null : this.password.toCharArray());
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
}
