package ServAuthority;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.TreeMap;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V1CertificateGenerator;

import Tools.Revocated;

@SuppressWarnings("deprecation")
public class ServerAuthority {
	private BouncyCastleProvider bc = new BouncyCastleProvider();
	private FileOutputStream fosS;
	private KeyPair kp;
	private PublicKey pkS;
	private PrivateKey prkS;
	private X509Certificate certif;
	private ServerSocket s;
	private Socket clientSock;
	private TreeMap<String,Revocated> revocated = new TreeMap<>();
	
	public ServerAuthority() {
		Security.addProvider(bc);
		serverCertif();	
		try {
			s = new ServerSocket(2324);
			System.out.println("CA listening....");
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	public void accept(){
		while(true){
			try {
				clientSock = s.accept();
				new Thread(new ServerAuthCon(clientSock, prkS,certif,revocated)).start();;
			} catch (IOException e) {
				System.err.println("decconexion");
				e.printStackTrace();
			}
		}
	}
	public void serverCertif(){
		try {
			kp = KeyPairGenerator.getInstance("RSA",bc).generateKeyPair();
			pkS = kp.getPublic();
			prkS = kp.getPrivate();
			X509V1CertificateGenerator cg = new X509V1CertificateGenerator();
			cg.setPublicKey(pkS);
			cg.setSerialNumber(BigInteger.valueOf(52111));
			cg.setSignatureAlgorithm("SHA1withRSA");
			cg.setIssuerDN(new X500Principal("CN=CA"));
			cg.setSubjectDN(new X500Principal("CN=Server"));
			cg.setNotBefore(new Date(System.currentTimeMillis()));
			cg.setNotAfter(new Date(System.currentTimeMillis()+100000000));
			certif = cg.generate(prkS);
			fosS = new FileOutputStream(new File("AuthorityRepertory/ServerCertif"));
			fosS.write(certif.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeyException |  SignatureException | IOException | CertificateEncodingException | IllegalStateException e) {
			e.printStackTrace();
		}
	}
	
}
