package ServAuthority;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@SuppressWarnings("deprecation")
public class CreateCSR {
	private BouncyCastleProvider bc = new BouncyCastleProvider();
	private PrivateKey pk;
	private KeyPair kp;
	private FileOutputStream fos;
	private PKCS10CertificationRequest csr;
	private String name;
	
	public CreateCSR(String name) {
		this.name = name;
	}
	
	public void sendCSR(){
		Security.addProvider(bc);
		try {
			kp = KeyPairGenerator.getInstance("RSA",bc).generateKeyPair();
			pk = kp.getPrivate();
			csr = new PKCS10CertificationRequest("SHA1withRSA",new X500Principal("CN="+name),kp.getPublic(),null,pk);
			fos = new FileOutputStream(new File("AuthorityRepertory/"+name));
			fos.write(csr.getEncoded());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			RSAPrivateKeySpec rpks = kf.getKeySpec(pk, RSAPrivateKeySpec.class);
			ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(new File("clientInfo/pk"+name)));
			oos.writeObject(rpks.getModulus());
			oos.writeObject(rpks.getPrivateExponent());
			oos.close();
		} catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException | IOException | InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}
	public static void main(String[] args) {
		CreateCSR create = new CreateCSR("Adam");
		create.sendCSR();
	}
}
