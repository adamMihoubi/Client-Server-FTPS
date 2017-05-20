package Client;

import java.io.IOException;
import java.net.Socket;
import Connexion.FTPOutput;
import Connexion.FTPProtocol;

public class Client  implements FTPProtocol{
	private Socket s;
	private String name;
	private String addr;
	private int port;
	private FTPInputClient in;
	private FTPOutput os;
	private ClientModel clientModel;
	
	public Client(String name, String addr, int port) {
		this.name = name;
		this.addr = addr;
		this.port = port;
		this.clientModel = new ClientModel(name);
	}
	
	public void connect(){
		try {
			Thread t = new Thread(new ClientAuthentification(clientModel,name));
			t.start();
			t.join();
			System.out.println("connexion au server FTP");
			s = new Socket(addr, port);
			os = new FTPOutput(s.getOutputStream());
			in = new FTPInputClient(this.name,s.getInputStream(), this);
			in.runnning();
			System.out.println("deconnexion");
			s.close();
		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
		
		
	}

	@Override
	public void sendFile(String name, int size, byte[] data) {
		byte[] encoded = clientModel.sendFile(name); 
		int s = encoded.length;
		os.sendFile(name, s, encoded);
	}

	@Override
	public void receiveFile(String name,byte[]encoded) {
		clientModel.receiveFile(name, encoded);	
	}

	@Override
	public void sendCertificat(String name, byte[] encoded) {
		os.sendCertificat(name, clientModel.sendMyCertif());
	}

	@Override
	public void receiveCertificat(String name, byte[] encoded) {
		System.out.println(name);
		System.out.println(clientModel.verifyCertificate(name, encoded));
		
	}
	@Override
	public void getSessionKey(byte[] sessionKey, byte[] signature) {
		clientModel.getSessionKey(sessionKey, signature);
	}
	
	@Override
	public void askFileList(String name) {
		os.askFileList(name);
	}
	@Override
	public void askFile(String name) {
		os.askFile(name);
	}
	@Override
	public void askFile(String name, String clientName) {
		os.askFile(name, clientName);
	}
	@Override
	public void receiveAuthFile(String name, byte[] encoded, byte[] signature) {
		clientModel.receiveFileAuth(name, encoded, signature);
	}
	
	@Override
	public void sendAuthFile(String name, String clientName, byte[] encoded, byte[] signature) {
		byte[] encode = clientModel.sendFileAuth(name);
		byte[] signFile =clientModel.sendFileSignature();
		os.sendAuthFile(name, clientName, encode, signFile);
		System.out.println("fichier envoyé");
	}
	
}
