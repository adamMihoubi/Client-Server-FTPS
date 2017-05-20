package Tools;

import java.util.ArrayList;
import java.util.Arrays;

public class Tools {
	public static boolean containingSpecificFormats(String name){
		String [] formatTab = {".jpg",".mp3",".mp4",".avi"};
		ArrayList<String> formats = new ArrayList<>(Arrays.asList(formatTab));
		for (String s: formats) {
			if(name.endsWith(s))return true;
		}
		return false;
	}
}
