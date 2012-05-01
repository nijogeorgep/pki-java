package Clients;

import java.util.Scanner;

public class ClientUtils {

	public static Integer readIntKeyboard() {
		Scanner sc = new Scanner(System.in);
		try {
			String s = sc.nextLine();
			return new Integer(s);
		}
		catch(Exception e) {
			return null;
		}
	}
	
	  public static String saisieString() {
	    Scanner sc = new Scanner(System.in);
	    String s = sc.nextLine();
	    return s;
	  }
	  
	
}
