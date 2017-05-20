package Tools;

public class Test {
	public static void main(String[] args) {
		long time = System.nanoTime()/1000000000;
		while(true){
			long end = System.nanoTime()/1000000000 - time ;
			if(end == 5){
				System.out.println(end);
				time = System.nanoTime()/1000000000;
			}
		}
	}
}
