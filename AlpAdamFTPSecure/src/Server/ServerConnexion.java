package Server;

import java.io.IOException;
import java.net.Socket;
import java.util.HashSet;

import javax.security.cert.CertificateException;
import javax.security.cert.X509Certificate;

import Connexion.FTPInput;
import Connexion.FTPOutput;
import Connexion.FTPProtocol;

public class ServerConnexion implements Runnable,FTPProtocol{
	private Socket s;
	private FTPInput fi;
	private FTPOutput fo;
	private String name;
	
	public ServerConnexion(String name,Socket s) throws IOException {
		this.s = s;
		this.name = name;
		
	}
	
	
	@Override
	public void run() {
		try {
			fo = new FTPOutput(s.getOutputStream());
			fi = new FTPInput(name,s.getInputStream(), this);
			fi.running();
		} catch (IOException e) {
			System.err.println("Client Disconnected "+ s.getInetAddress());
		}
		
		
	}


	@Override
	public void sendFile(String name, int size,byte[]data) {
		byte[] encoded = ServerModel.sendFile(name, this.name);
		int s = encoded.length;
		System.out.println("fichier envoyé "+ name);
		fo.sendFile(name, s,encoded);
	}


	@Override
	public void receiveFile(String name,byte[]encoded) {
		ServerModel.receiveFile(name, this.name, encoded);
	}
	
	@Override
	public void sendAuthFile(String name,String clientName, byte[] encoded, byte[] signature) {
		byte [] data = ServerModel.sendFileAuth(name,clientName);
		System.out.println("SeverConnx data envoyé" + data.length);
		fo.sendAuthFile(name,data, ServerModel.sendFileSignature());
	}
	@Override
	public void receiveAuthFile(String name, String clientName, byte[] encoded, byte[] signature) {
		ServerModel.receiveFileAuth(name, clientName, encoded, signature);
	}

	@Override
	public void sendCertificat(String name, byte[] encoded) {
		fo.sendCertificat(name, ServerModel.sendMyCertif());
	}


	@Override
	public void receiveCertificat(String name, byte[] encoded) {
		X509Certificate certif;
		try {
			certif = X509Certificate.getInstance(encoded);
			if(ServerModel.verifyCertificate(name, encoded)){
				ServerModel.putCertificate(name, certif);
				this.name = name;
			}
			else System.err.println("Faux certificat");
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	@Override
	public void sendSessionKey(byte[] signature,byte[] sessionKey) {
		fo.sendSessionKey(ServerModel.generateSessionKey(name),ServerModel.generateSignature());
	}
	@Override
	public void sendFileList(String clientName,HashSet<String> fileList) {
		fo.sendFileList(clientName,ServerModel.sendFileList(clientName));
	}

}
