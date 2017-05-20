package Connexion;

import java.util.HashSet;

public interface FTPProtocol {
	
	public void sendFile(String name,int size,byte[] data);
	public default void receiveFile(String name,byte[]data){}
	public void sendCertificat(String name, byte[] encoded);
	public default void receiveCertificat(String name,byte[] encoded){}
	public default void sendSessionKey(byte[]sessionKey,byte[] signature){}
	public default void getSessionKey(byte[] sessionKey,byte[] signature){}
	public default void askFileList(String name){}
	public default void askFile(String name){}
	public default void askFile(String name,String clientName){}
	public default void sendFileList(String clientName,HashSet<String> fileList){}
	public default void sendAuthFile(String name, String clientName,byte[]encoded,byte[] signature){}
	public default void sendAuthFile(String name,byte[]encoded,byte[] signature){}
	public default void receiveAuthFile(String name,byte[]encoded,byte[] signature){}
	public default void receiveAuthFile(String name,String clientName,byte[]encoded,byte[] signature){}
	
}
