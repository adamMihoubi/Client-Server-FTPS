package Server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {
	private ServerSocket s;
	private Socket clientSock;
	private String name;

	public Server(String name) {
		try {
			this.name = name;
			Thread t = new Thread(new ServerFTPAuth(this.name));
			t.start();
			t.join();
			s = new ServerSocket(9292);
			System.out.println("Server listening...");
		} catch (IOException | InterruptedException e) {
			System.err.println("Port already in use.");
			System.exit(1);
		}
	}

	public void accept() {
		while (true) {
			try {
				System.out.println("accept");
				clientSock = s.accept();
				new Thread(new ServerConnexion(this.name,clientSock)).start();
			} catch (IOException e) {
				System.err.println("Error in communication");
				e.printStackTrace();
			}
		}
	}
}
