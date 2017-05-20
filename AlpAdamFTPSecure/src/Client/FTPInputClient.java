package Client;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

import Connexion.FTPProtocol;

public class FTPInputClient {
	private InputStream in;
	private FTPProtocol handler;
	private boolean stop = true;
	private String name;
	private String serName;

	public FTPInputClient(String name, InputStream in, FTPProtocol handler) {
		this.in = in;
		this.handler = handler;
		this.name = name;
	}

	public void runnning() {
		try {
			handler.sendCertificat(name, null);
			DataInputStream is = new DataInputStream(in);
			String msg = is.readUTF();
			if (!msg.equals("certificate"))
				stop = false;
			serName = is.readUTF();
			int size = is.readInt();
			byte[] encoded = new byte[size];
			is.read(encoded);
			handler.receiveCertificat(serName, encoded);
			System.out.println("reception du certificat de " + serName);
			msg = is.readUTF();
			if (!msg.equals("session"))
				stop = false;
			size = is.readInt();
			byte[] ssKey = new byte[size];
			int stream = 0;
			int lu =0;
			while(stream<size){
				lu = is.read(ssKey,stream,size-stream);
				stream = stream + lu;
			}
			size = is.readInt();
			byte[] sign = new byte[size];
			is.read(sign);
			handler.getSessionKey(ssKey, sign);
			System.out.println("reception de la clef de session");
			long startTime = System.nanoTime()/1000000000;
			Scanner choice = null;
			while (stop) {
				 choice = new Scanner(System.in);
				//Verifie la revocation apres 5 secondes
				verifyRevocation(startTime);
				System.out.println("tapez 1 pour un trasfert de fichier authentifié \n "
						+ "2 pour un transfert de fichier cryptés");
				String ch = choice.nextLine().trim();
				if (ch.equals("1")) {
					System.out.println(
							"tapez \n'get' pour telecharger un fichier sur le serveur \n'send' pour envoyer un fichier authentifié");
					ch = choice.nextLine().trim();
					if (ch.equals("send")) {
						System.out.println("taper le nom du fichier signé a envoyer");
						String filename = choice.nextLine().trim();
						handler.sendAuthFile(filename,this.name, null,null);
					} 
					else if(ch.equals("get")){
						handler.askFileList(this.name);
						msg = is.readUTF();
						size = is.readInt();
						for (int i = 0; i < size; i++)
							System.out.println(is.readUTF());
						System.out.println("taper le nom du fichier signé voulu :");
						String file = choice.nextLine();
						handler.askFile(file, name);
						msg = is.readUTF();
						String name = is.readUTF();
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
						handler.receiveAuthFile(name, encoded, signFile);
					}else System.err.println("reessayer");
				}
				else if (ch.equals("2")) {
					System.out.println(
							"tapez \n'get' pour telecharger un fichier sur le serveur \n'send' pour envoyer un fichier Crypté");
					
					ch = choice.nextLine().trim();
					if (ch.equals("send")) {
						System.out.println("taper le nom du fichier a envoyer");
						String filename = choice.nextLine().trim();
						handler.sendFile(filename, 0, null);
					} else if (ch.equals("get")) {
						handler.askFileList(this.name);
						msg = is.readUTF();
						size = is.readInt();
						for (int i = 0; i < size; i++)
							System.out.println(is.readUTF());
						System.out.println("taper le nom du fichier voulu :");
						String file = choice.nextLine().trim();
						handler.askFile(file);
						msg = is.readUTF();
						file = is.readUTF();
						size = is.readInt();
						encoded = new byte[size];
						stream = 0;
						lu = 0;
						while (stream < size) {
							System.out.println("stream : " + stream);
							lu = is.read(encoded, stream, size - stream);
							System.out.println("lu :" + lu);
							stream = stream + lu;
							System.out.println(stream);
						}
						handler.receiveFile(file, encoded);
					} else
						System.err.println("ressayer");
				}else System.err.println("ressayer");
				
			}
		} catch (IOException  e) {
			
			e.printStackTrace();
			
			
		}
	}
	private void verifyRevocation(long startTime){
		long end = System.nanoTime()/1000000000 - startTime;
		System.out.println(end);
		if(end>5){
			Thread t = new Thread(new ClientAuthentification(serName,"verify"));
			t.start();
			try {
				t.join();
				startTime = System.nanoTime()/1000000000;
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			
		}
	}
}
