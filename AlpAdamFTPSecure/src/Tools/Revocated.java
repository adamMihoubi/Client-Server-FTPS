package Tools;

import java.io.DataOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;

import java.security.cert.X509Certificate;

public class Revocated {
	private X509Certificate certificate;
	private Reasons reason;

	public Revocated(Certificate certif, Reasons reason) {
		this.certificate = (X509Certificate) certif;
		this.reason = reason;
	}
	
	public void sendRevocation(DataOutputStream dos) throws IOException{
		String serial = certificate.getSerialNumber().toString();
		String reas = reason.toString();
		dos.writeUTF(serial);
		dos.writeUTF(reas);
	}
	
	
}
