package Utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Config {

	public static String file = "config";
	
	public static void checkConfigFile() {
		File f  = new File(file);
		if (!(f.exists())) {
			System.out.println("Config file :"+file + " not found!");
			System.exit(1);
		}
	}
	
	public static String get(String attribute, String default_val) {
		try {
			Properties prop = new Properties();
		    InputStream is = new FileInputStream(file);
	
		    prop.load(is);
		    
			return prop.getProperty(attribute,default_val);
		} 
		catch(IOException e) {
			return null;
		}
	}

}
