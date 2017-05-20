package Client;

public class AppClient {
	public static void main(String[] args) {
		Client c = new Client("Adam","localhost", 9292);
		c.connect();
	}
}
