package Client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ClientModel {
	private SecretKey sk;
	private PublicKey pk;
	private PrivateKey prk;
	private X509Certificate certif, certifServ,certifSession;
	private byte[] signatureFile;
	private String name;
	
	public ClientModel(String name) {
		this.name = name;
	}
	
	public void getPrivateKey(){
		RSAPrivateKeySpec rpks;
		ObjectInputStream ois;
		try {
			ois = new ObjectInputStream(new FileInputStream(new File("clientInfo/pk"+name)));
			BigInteger mod = (BigInteger) ois.readObject();
			BigInteger exp = (BigInteger) ois.readObject();
			ois.close();
			rpks = new RSAPrivateKeySpec(mod, exp);
			prk = KeyFactory.getInstance("RSA", new BouncyCastleProvider()).generatePrivate(rpks);
		} catch (IOException | ClassNotFoundException | InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
	}
	public void receiveMyCertif(X509Certificate cer) {
		System.out.println("Mon certif Reçu");
		certif = cer;
	}

	public void receiveServerCertif(X509Certificate cer) {
		System.out.println("reception du serveur certif");
		certifServ = cer;
	}

	public void verify() {
		getPrivateKey();
		try {
			certif.verify(certifServ.getPublicKey());
			System.out.println("Certificat a bien été signé par la CA");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			System.err.println("Certificat non signé par la CA ");
		}
	}

	public byte[] sendMyCertif() {
		try {
			Security.addProvider(new BouncyCastleProvider());
			;
			return certif.getEncoded();
		} catch (CertificateException e) {
			e.printStackTrace();
		}
		return null;
	}

	public boolean verifyCertificate(String name, byte[] encoded) {
		Security.addProvider(new BouncyCastleProvider());
		boolean res = false;
		try {
			certifSession = X509Certificate.getInstance(encoded);
			pk = certifSession.getPublicKey();
			certifSession.verify(certifServ.getPublicKey());
			res = certifSession.getSubjectDN().getName().equals("CN="+name);
		} catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException
				| SignatureException e1) {
			e1.printStackTrace();
		}
		System.out.println("verification ....");
		return res;
	}

	public void getSessionKey(byte[] secretEmcoded, byte[] signature) {
		System.out.println("test du getSession");
		try {
			Signature s = Signature.getInstance("SHA1withRSA");
			s.initVerify(pk);
			s.update(secretEmcoded);
			if (s.verify(signature)) {
				Cipher c = Cipher.getInstance("RSA");
				c.init(Cipher.DECRYPT_MODE, prk);
				byte[]sessionKey = c.doFinal(secretEmcoded);
				SecretKeySpec skp = new SecretKeySpec(sessionKey, "AES");
				sk = SecretKeyFactory.getInstance("AES").generateSecret(skp);
				System.out.println("Generation de la clé de session");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
	}

	public byte[] sendFile(String name) {
		try {
			FileInputStream fis = new FileInputStream(new File("clientfile/" + name));
			byte[] data = new byte[fis.available()];
			fis.read(data);
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING","BC");
			c.init(Cipher.ENCRYPT_MODE, sk,new IvParameterSpec("AdamAlpiIvVector".getBytes()));
			byte[] encryptedData = c.doFinal(data);
			fis.close();
			return encryptedData;
		} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException  e) {
			e.printStackTrace();
		}
		return new byte[10];
	}
	
	public void receiveFile(String name, byte[] encrypted) {
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING","BC");
			System.out.println("encrypted  : "+encrypted.length);
			c.init(Cipher.DECRYPT_MODE, sk,new IvParameterSpec("AdamAlpiIvVector".getBytes()));
			byte[] decypt = c.doFinal(encrypted);
			System.out.println("decryptéé : "+decypt.length);
			FileOutputStream fos = new FileOutputStream(new File("clientfile/" + name));
			fos.write(decypt);
			fos.close();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | IOException | InvalidAlgorithmParameterException | NoSuchProviderException  e) {
			e.printStackTrace();
		}

	}
	
	public void receiveFileAuth(String name, byte[] encrypted, byte[] signature){
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(certifSession.getPublicKey());
			s.update(encrypted);
			if(s.verify(signature)){
				FileOutputStream fos = new FileOutputStream(new File("clientfile/"+name));
				fos.write(encrypted);
				fos.close();
			}//Gérer lexception Signature de facon a couper la connexion
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
			e.printStackTrace();
		}
	}
	
	public  byte[] sendFileAuth(String name){
		try {
			FileInputStream fis = new FileInputStream(new File("clientfile/"+name));
			byte[] encrypted = new byte[fis.available()];
			fis.read(encrypted);
			fis.close();
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(prk);
			s.update(encrypted);
			signatureFile = s.sign();
			return encrypted;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException  | IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] sendFileSignature(){
		return signatureFile;
	}
	
}
