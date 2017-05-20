package Client;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

public class ClientAuthentification implements Runnable{	
	private String name;
	private Socket s;
	private ClientModel clientModel;
	private String task;

	

	public ClientAuthentification(ClientModel clientModel,String name) {
		this.name = name;
		this.clientModel = clientModel;
		this.task = "get";
	}
	
	public ClientAuthentification(String name,String task) {
		this.name = name;
		this.task = task;
	}
	
	
	@Override
	public void run() {
		try {
			s = new Socket("localhost", 2324);
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			DataInputStream dis = new DataInputStream(s.getInputStream());
			switch(task){
			case "get":
				dos.writeUTF(task);
				dos.writeUTF(name);
				byte[] encoded = new byte[dis.readInt()];
				dis.read(encoded);
				X509Certificate certif = X509Certificate.getInstance(encoded);
				clientModel.receiveMyCertif(certif);
				byte[] encodedServ = new byte[dis.readInt()];
				dis.read(encodedServ);
				X509Certificate certifServ = X509Certificate.getInstance(encodedServ);
				clientModel.receiveServerCertif(certifServ);
				clientModel.verify();
				System.out.println("transfert terminé...");
				break;
			case "verify":
				dos.writeUTF(task);
				dos.writeUTF(name);
				System.out.println(dis.readUTF());
				System.out.println(dis.readUTF());
				System.out.println(dis.readUTF());
				break;
			}
			s.close();
			
			
		} catch (IOException | CertificateException  e) {
			e.printStackTrace();
		}
		
	}
	



	
	
}
