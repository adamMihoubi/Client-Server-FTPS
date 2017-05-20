package ServAuthority;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.TreeMap;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import Tools.Reasons;
import Tools.Revocated;

@SuppressWarnings("deprecation")
public class ServerAuthCon implements Runnable {
	private PKCS10CertificationRequest csrClient;
	private ASN1InputStream ans1;
	private String clientName;
	private PrivateKey prkS;
	private X509Certificate certif, certifServ;
	private FileInputStream fis;
	private Socket s;
	private KeyStore ks;
	private TreeMap<String, Revocated> revocated;

	public ServerAuthCon(Socket s, PrivateKey prkS, X509Certificate certifServ, TreeMap<String, Revocated> revocated) {
		this.s = s;
		this.prkS = prkS;
		this.certifServ = certifServ;
		this.revocated = revocated;

		try {
			ks = KeyStore.getInstance("JKS");
			try {
				this.fis = new FileInputStream(new File("AuthorityRepertory/keystore"));
				ks.load(fis, "pass".toCharArray());
				System.out.println("Load du fichier");
			} catch (FileNotFoundException e1) {
				System.out.println("load null");
				ks.load(null, null);
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			try {
				ks.load(null, null);
			} catch (NoSuchAlgorithmException | CertificateException | IOException e1) {
				e1.printStackTrace();
			}
		}
	}

	@Override
	public void run() {
		try {
			DataInputStream dis = new DataInputStream(s.getInputStream());
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			String msg = dis.readUTF();
			if (msg.equals("get")) {
				this.clientName = dis.readUTF();
				if (!verifyRevocated())
					createCertif();
				else
					s.close();
				byte[] encoded = certif.getEncoded();
				dos.writeInt(encoded.length);
				dos.write(encoded);
				System.out.println("envoie du certificat du serveur ...");
				byte[] encodedCA = certifServ.getEncoded();
				dos.writeInt(encodedCA.length);
				dos.write(encodedCA);
				dos.flush();
				System.out.println("transfert des certificats terminés.");
			}
			if (msg.equals("verify")) {
				this.clientName = dis.readUTF();
				if (verifyRevocated()) {
					dos.writeUTF("revocated");
					Revocated r = revocated.get(clientName);
					r.sendRevocation(dos);
					dos.flush();
				}
				else {
					dos.writeUTF("The Client :");
					dos.writeUTF(clientName);
					dos.writeUTF("is not revocated");
				}
			}
			if (msg.equals("killme")) {
				this.clientName = dis.readUTF();
				createCRL(clientName, Reasons.Cessation_Of_Operation);
			}
		} catch (IOException | CertificateEncodingException e) {
			e.printStackTrace();
		}

	}

	private boolean verifyRevocated() {
		synchronized (revocated) {
			return revocated.containsKey(clientName);
		}
	}

	private void createCRL(String name, Reasons reason){
		synchronized (revocated) {
			Certificate certif;
			try {
				certif = ks.getCertificate(name);
				revocated.put(name, new Revocated(certif,reason));
			} catch (KeyStoreException e) {
				e.printStackTrace();
			}
		}
	}

	private void createCertif() {
		try {
			FileOutputStream fos = new FileOutputStream(new File("AuthorityRepertory/keystore"));
			if (ks.containsAlias(clientName)) {
				certif = (X509Certificate) ks.getCertificate(clientName);
				System.out.println("certif existant load dans le keystore");
				if (ks.containsAlias("CA")) {
					certifServ = (X509Certificate) ks.getCertificate("CA");
				}
			} else {
				ans1 = new ASN1InputStream(new FileInputStream(new File("AuthorityRepertory/" + clientName)));
				ASN1Primitive anp = ans1.readObject();
				csrClient = new PKCS10CertificationRequest(anp.getEncoded());
				if (csrClient.verify()) {
					X509V1CertificateGenerator cg = new X509V1CertificateGenerator();
					cg.setPublicKey(csrClient.getPublicKey());
					cg.setSerialNumber(BigInteger.valueOf(15248));
					cg.setIssuerDN(new X500Principal("CN=CA"));
					cg.setSubjectDN(new X500Principal("CN=" + clientName));
					cg.setSignatureAlgorithm("SHA1withRSA");
					cg.setNotBefore(new Date(System.currentTimeMillis()));
					cg.setNotAfter(new Date(System.currentTimeMillis() + 1000000000));
					certif = cg.generate(prkS);
					ks.setCertificateEntry(clientName, certif);
					ks.setCertificateEntry("CA", certifServ);
					ks.store(fos, "pass".toCharArray());
				} else
					System.err.println("Csr corrompu");
				fos.close();
				ans1.close();
			}

		} catch (IOException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
				| IllegalStateException | SignatureException | KeyStoreException | CertificateException e) {
			e.printStackTrace();
		}

	}

}
