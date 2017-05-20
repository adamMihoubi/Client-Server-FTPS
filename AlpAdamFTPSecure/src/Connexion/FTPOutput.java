package Connexion;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashSet;

public class FTPOutput implements FTPProtocol {
	private DataOutputStream os;

	public FTPOutput(OutputStream out) {
		os = new DataOutputStream(out);
	}

	@Override
	public void sendFile(String name, int size, byte[] data) {
		try {
			os.writeUTF("file");
			os.writeUTF(name);
			os.writeInt(size);
			os.write(data);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public void askFileList(String name) {
		try {
			os.writeUTF("ask");
			os.writeUTF(name);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sendFileList(String clientName,HashSet<String> fileList) {
		try {
			os.writeUTF("fileList");
			os.writeInt(fileList.size());
			os.flush();
			for (String string : fileList) {
				os.writeUTF(string);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sendCertificat(String name, byte[] encoded) {
		try {
			os.writeUTF("certificate");
			os.writeUTF(name);
			os.writeInt(encoded.length);
			os.write(encoded);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void askFile(String name) {
		try {
			os.writeUTF("get");
			os.writeUTF(name);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void askFile(String name, String clientName) {
		try {
			os.writeUTF("askauthfile");
			System.out.println("demande fichier");
			os.writeUTF(name);
			os.writeUTF(clientName);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sendSessionKey(byte[] sessionKey, byte[] signature) {
		try {
			os.writeUTF("session");
			os.writeInt(sessionKey.length);
			os.write(sessionKey);
			os.writeInt(signature.length);
			os.write(signature);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public void sendAuthFile(String name, byte[] encoded, byte[] signature) {
		try {
			os.writeUTF("authfile");
			os.writeUTF(name);
			os.writeInt(encoded.length);
			os.write(encoded);
			os.writeInt(signature.length);
			os.write(signature);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	@Override
	public void sendAuthFile(String name, String clientName, byte[] encoded, byte[] signature) {
		try {
			os.writeUTF("authfile");
			os.writeUTF(name);
			os.writeUTF(clientName);
			os.writeInt(encoded.length);
			os.write(encoded);
			os.writeInt(signature.length);
			os.write(signature);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

}
