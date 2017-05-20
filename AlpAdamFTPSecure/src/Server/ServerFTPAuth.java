package Server;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Security;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class ServerFTPAuth implements Runnable{
	private String name;
	private Socket s;
	private BouncyCastleProvider bc = new BouncyCastleProvider();

	
	public ServerFTPAuth(String name) {
		this.name = name;
		
		
	}
	@Override
	public void run() {
		Security.addProvider(bc);
		try {
			s = new Socket("localhost", 2324);
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			dos.writeUTF("get");
			dos.writeUTF(name);
			DataInputStream dis = new DataInputStream(s.getInputStream());
			byte[] encoded = new byte[dis.readInt()];
			dis.read(encoded);
			X509Certificate certif = X509Certificate.getInstance(encoded);
			ServerModel.receiveMyCertif(certif);
			byte[] encodedServ = new byte[dis.readInt()];
			dis.read(encodedServ);
			X509Certificate certifServ = X509Certificate.getInstance(encodedServ);
			ServerModel.receiveServerCertif(certifServ);
			ServerModel.verify();
			System.out.println("transfert terminé...");
			s.close();
		} catch (IOException | CertificateException  e) {
			e.printStackTrace();
		}
	}
}
