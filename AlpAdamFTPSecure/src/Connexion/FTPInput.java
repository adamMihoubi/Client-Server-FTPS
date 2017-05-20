package Connexion;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class FTPInput {
	private FTPProtocol handler;
	private InputStream in;
	private boolean running = true;
	private String name;
	
	public FTPInput(String name,InputStream in, FTPProtocol handler) {
		this.in = in;
		this.handler = handler;
		this.name = name;
	}
	
	public void running() throws IOException{
		try{
		DataInputStream is = new DataInputStream(in);
		System.out.println("Connectééé");
		String msg = is.readUTF();
		if(!msg.equals("certificate"))running = false;
		String name = is.readUTF();
		int size = is.readInt();
		byte[] encoded = new byte[size];
		is.read(encoded);
		handler.receiveCertificat(name, encoded);
		System.out.println("reception du certificat de "+name);
		handler.sendCertificat(this.name, encoded);
		System.out.println("Envoie de mon certif");
		handler.sendSessionKey(null,null);
		
		while(running){
			String msg2 = is.readUTF();
			switch(msg2){
			case "file":
				name = is.readUTF();
				size = is.readInt();
				encoded = new byte[size];
				int stream = 0;
				int lu =0;
				while(stream<size){
					System.out.println("stream : " +stream);
					lu = is.read(encoded,stream,size-stream);
					System.out.println("lu :" + lu);
					stream = stream + lu;
					System.out.println(stream);
				}
				handler.receiveFile(name,encoded);
				break;
			case "get":
				name = is.readUTF();
				System.out.println("demande du fichier : "+name);
				handler.sendFile(name, 0,null);
				break;
			case "ask":
				System.out.println("demande de liste de fichier ");
				name = is.readUTF();
				handler.sendFileList(name,null);
				break;
			case "askauthfile":
				name = is.readUTF();
				String cname = is.readUTF();
				System.out.println("demande du fichier authentifié : " + name);
				handler.sendAuthFile(name,cname,null,null);
				break;
			case "authfile":
				System.out.println("le client envoie un fichier");
				name = is.readUTF();
				String clientName = is.readUTF();
				size = is.readInt();
				encoded = new byte[size];
				stream = 0;
				lu =0;
				while(stream<size){
					System.out.println("stream : " +stream);
					lu = is.read(encoded,stream,size-stream);
					System.out.println("lu :" + lu);
					stream = stream + lu;
					System.out.println(stream);
				}
				int signlenght = is.readInt();
				byte []signFile = new byte[signlenght];
				is.read(signFile);
				handler.receiveAuthFile(name, clientName, encoded, signFile);
			break;	
			}
			
		}
		}catch (EOFException e) {
			System.err.println("message innatendu");
			
		}	
	}
}
