package Utils;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {

	public static String get(String attribute, String default_val) {
		try {
			Properties prop = new Properties();
		    InputStream is = new FileInputStream("config");
	
		    prop.load(is);
		    
			return prop.getProperty(attribute,default_val);
		} 
		catch(IOException e) {
			return null;
		}
	}
	
	public static void main(String[] args) throws IOException {
		System.out.println(Config.get("BASE_URL", "localhost"));
	}
}
