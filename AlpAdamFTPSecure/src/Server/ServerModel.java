package Server;

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
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.HashSet;
import java.util.TreeMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.security.cert.CertificateEncodingException;
import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class ServerModel {

	private static TreeMap<String, X509Certificate> clientCertificates = new TreeMap<>();
	private static HashSet<String> fileSet = new HashSet<>();
	private static TreeMap<String,SecretKey> sessionKeys = new TreeMap<>();
	private static PrivateKey ppk;
	private static byte[] signature,signatureFile;
	private static X509Certificate certif, certifServ;	

	public static void receiveMyCertif(X509Certificate cer) {
		System.out.println("Mon certif Reçu");
		certif = cer;
	}

	public static void receiveServerCertif(X509Certificate cer) {
		System.out.println("reception du serveur certif");
		certifServ = cer;
	}

	public static void verify() {
		try {
			certif.verify(certifServ.getPublicKey());
			System.out.println("Certificat a bien été signé par la CA");
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | CertificateException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			System.err.println("Certificat non signé par la CA ");
		}
	}

	public static synchronized void putCertificate(String name, X509Certificate certificate) {
		if (!isExist(name)) {
			clientCertificates.put(name, certificate);
			File f = new File("serverfile/"+name);
			if(f.mkdir())System.out.println("repertoire client crée");;
			System.out.println(clientCertificates);
		}
	}

	public static synchronized void receiveFile(String name, int size, byte[] data) {
		if (!existFile(name)) {
			fileSet.add(name);
		}
	}

	public static synchronized byte[] sendServCertif() {
		try {
			return certifServ.getEncoded();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static synchronized byte[] sendMyCertif() {
		try {
			return certif.getEncoded();
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static boolean existFile(String name) {
		return fileSet.contains(name);
	}

	public static synchronized boolean isExist(String name) {
		return clientCertificates.containsKey(name);
	}

	public static boolean verifyCertificate(String name, byte[] encoded) {
		Security.addProvider(new BouncyCastleProvider());
		boolean res = false;
		X509Certificate certif;
		try {
			certif = X509Certificate.getInstance(encoded);
			certif.verify(certifServ.getPublicKey());
			res = certif.getSubjectDN().getName().equals("CN="+name);
		} catch (CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e1) {
			e1.printStackTrace();
		}
		System.out.println("verification ....");
		return res;
	}

	public static synchronized byte[] generateSessionKey(String name) {
		SecretKey sk = null;
		RSAPrivateKeySpec rpks;
		byte [] encryptedKey = null;
		try {
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(128);
			sk = kg.generateKey();
			sessionKeys.put(name, sk);
			Cipher c = Cipher.getInstance("RSA");
			X509Certificate cer = clientCertificates.get(name);
			c.init(Cipher.ENCRYPT_MODE,cer.getPublicKey());
			encryptedKey = c.doFinal(sk.getEncoded());
			System.out.println(sessionKeys);
			ObjectInputStream ois = new ObjectInputStream(new FileInputStream(new File("clientInfo/pk"+name)));
			BigInteger mod = (BigInteger) ois.readObject();
			BigInteger exp = (BigInteger) ois.readObject();
			ois.close();
			rpks = new RSAPrivateKeySpec(mod, exp);
			ppk = KeyFactory.getInstance("RSA", new BouncyCastleProvider()).generatePrivate(rpks);
			Signature s = Signature.getInstance("SHA1withRSA");
			s.initSign(ppk);
			s.update(encryptedKey);
			signature = s.sign();
		} catch (IOException | ClassNotFoundException | InvalidKeySpecException | NoSuchAlgorithmException
				| InvalidKeyException | SignatureException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {

			e.printStackTrace();
		}
		return encryptedKey;
	}

	public static synchronized byte[] generateSignature() {
		return signature;
	}
	
	public synchronized static byte[] sendFile(String name,String clientName){
		SecretKey sk = sessionKeys.get(clientName);
			try {
				FileInputStream fis = new FileInputStream (new File("serverfile/"+clientName+"/"+name));
				byte[] data = new byte[fis.available()];
				fis.read(data);
				Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
				c.init(Cipher.ENCRYPT_MODE, sk,new IvParameterSpec("AdamAlpiIvVector".getBytes()));
				byte[] encryptedData = c.doFinal(data);
				fis.close();
				return encryptedData;
			} catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			}
		
		return null;	
	}
	
	
	
	public synchronized static void receiveFile(String name,String clientName,byte[] encrypted){
		SecretKey sk = sessionKeys.get(clientName);
		System.out.println("Client Name :"+clientName);
		try {
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING","BC");			
			c.init(Cipher.DECRYPT_MODE,sk,new IvParameterSpec("AdamAlpiIvVector".getBytes()));
			System.out.println("file lenght : "+encrypted.length);
			byte[] decypt = c.doFinal(encrypted);
			System.out.println("do final : " + decypt.length);
			FileOutputStream fos = new FileOutputStream(new File("serverfile/"+clientName+"/"+name));
			fos.write(decypt);
			fos.close();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException  | IOException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			e.printStackTrace();
		}
	}
	
	public synchronized static  void receiveFileAuth(String name,String clientName, byte[] encrypted, byte[] signature){
		X509Certificate certifSession = clientCertificates.get(clientName);
		System.out.println("Client Name :"+clientName);
		try {
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initVerify(certifSession.getPublicKey());
			s.update(encrypted);
			if(s.verify(signature)){
				FileOutputStream fos = new FileOutputStream(new File("serverfile/"+clientName+"/"+name));
				fos.write(encrypted);
				fos.close();
				System.out.println("fichier "+name+" a été reçu");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | IOException e) {
			e.printStackTrace();
		}
	}
	
	public synchronized static byte[] sendFileAuth(String name,String clientName){
		try {
			FileInputStream fis = new FileInputStream(new File("serverfile/"+clientName+"/"+name));
			byte[] encrypted = new byte[fis.available()];
			fis.read(encrypted);
			fis.close();
			Signature s = Signature.getInstance("SHA256withRSA");
			s.initSign(ppk);
			s.update(encrypted);
			signatureFile = s.sign();
			return encrypted;
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException  | IOException e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public synchronized static byte[] sendFileSignature(){
		return signatureFile;
	}
	
	public synchronized static HashSet<String> sendFileList(String clientName){
		System.out.println("Liste fichier name client : " + clientName);
		HashSet<String> set = new HashSet<>();
		File repertory = new File("serverfile/"+clientName);
		String[] l = repertory.list();
		for(int i=0;i<l.length;i++)set.add(l[i]);
		return set;
	}

}
