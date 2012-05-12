package Admin;

import java.io.IOException;
import java.util.Scanner;

import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;
import Utils.Config;
import Utils.PasswordUtils;

public class UserManager {
	
	  public static void main(String[]args) {
			String pass = PasswordUtils.readInPassword("LDAP: "); // Read LDAP password because all the following operations modify it.
			if (!(ldaputils.isPasswordValid(pass))) {
				System.out.println("Wrong password");
				System.exit(1);
			}
		    
		    char al ;
		    do {
			      System.out.println("Options: ");
			      System.out.println("1 - Add new user");
			      System.out.println("2 - Delete user");
			      System.out.println("q - Quit");
			      al = saisie();
			      switch(al) {
			        case('1'): createClient(pass);
			          break;
			        case('2'): deleteClient(pass);
			          break;
			      }     
		    } while(!(al=='q'));
	  }
	  
	  private static void deleteClient(String pass) {
	/**
	 * 
	 */
	    try {
		      String surname, commonname;
		      System.out.print("Enter the surname of the user to delete: ");
		      surname = saisieString();
		      System.out.print("Enter the firstname of th user to delete: ");
		      commonname = saisieString();
		      System.out.println(ldaputils.getUIDFromSubject("CN="+commonname.replace(" ", "-") + " " + surname.replace(" ", "-")));
		      String uid = "uid="+ldaputils.getUIDFromSubject("CN="+commonname.replace(" ", "-") + " " + surname.replace(" ", "-"));
		      ldaputils.deleteUser(uid+";"+ Config.get("USERS_BASE_DN", ""),pass); // Call the ldaputils methods that delete the user
		      System.out.println("User deleted with success");
	    }
	    catch (Exception e) {
		      System.out.println("User not found");
		      e.printStackTrace();
	    }
	  }
	
	  private static void createClient(String pass) {
	      String surname,commonname,pwd,uid ;
	      System.out.print("Enter the surname: "); // Read all the required field
	      surname = saisieString();
	      System.out.print("Enter the firstname: ");
	      commonname = saisieString();
	      System.out.print("Enter the password: ");
	      pwd = saisieString();
	      
	      uid = String.valueOf(System.currentTimeMillis());
	      try {
	        ldaputils.createNewUser(uid, commonname.replace(" ", "-"), surname.replace(" ", "-"), MessageDigestUtils.digest(pwd),pass);
	        System.out.println("User added with success");
	      }
	      catch (IOException e) {
	        System.out.println("Error during user addition.");
	        e.printStackTrace();
	      }
	  }
	
	  private static char saisie() {
		    char io = ' ';
		    Scanner sc = new Scanner(System.in);
		    io = sc.next().charAt(0);
		    return io;
	  }
	  
	  private static String saisieString() {
			Scanner sc = new Scanner(System.in);
			String s = null;
			s = sc.nextLine();
			return s;
	  }
}
