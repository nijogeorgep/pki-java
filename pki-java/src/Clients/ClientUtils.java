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
	  
	  public static String readIdentity() {
		  String surname,commonname;
		    System.out.print("Nom: ");
		    surname = ClientUtils.saisieString();
		    System.out.print("Prenom: ");
		    commonname = ClientUtils.saisieString();
		    return commonname.replace(" ", "-") + " " + surname.replace(" ", "-");
	  }
	  
	  public static int makeChoice(String title, String choice1, String choice2){
			Integer val = null;
			boolean isOK = true;
			try {
				
				do {
				    System.out.println(title);
				    System.out.println("1 - "+choice1);
				    System.out.println("2 - "+choice2);
				    val = ClientUtils.readIntKeyboard();
				    if(val == null)
				    	continue;
				    else
				    	if(val >= 1 && val <=2)
				    		isOK= false;
				}while (isOK);
			}
			catch(Exception e) {
				e.printStackTrace();
			}
			return val;
	  }
	
}
