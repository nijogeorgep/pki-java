package Admin;

import java.io.IOException;
import java.util.Scanner;

import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;
import Utils.Config;
import Utils.PasswordUtils;

public class UserManager
{
  public static void main(String[]args)
  {
	String pass = PasswordUtils.readInPassword("LDAP");
	if (!(ldaputils.isPasswordValid(pass))) {
		System.out.println("Wrong password");
		System.exit(1);
	}
    System.out.println(new String(ldaputils.getUserPassword("1234",pass))); 
    System.out.println(new String(MessageDigestUtils.digest("coucou")));
    System.out.println(MessageDigestUtils.checkDigest(MessageDigestUtils.digest("coucou"),new String(ldaputils.getUserPassword("1234",pass)).getBytes() ));
   
    
    char al ;
    do
    {
      System.out.println("Options ");
      System.out.println("1 - Ajouter un utilisateur ");
      System.out.println("2 - Supprimer un utilisateur ");
      System.out.println("q - Quitter ");
      al = saisie();
      switch(al)
      {
        case('1'): createClient(pass);
          break;
        case('2'): deleteClient(pass);
          break;
      }
          
    } while(!(al=='q'));
   
  }
  
  private static void deleteClient(String pass)
  {
    try
    {
      String surname, commonname;
      System.out.println("Entrez le nom de l'utilisateur a supprimer");
      surname = saisieString();
      System.out.println("Entrez le pr�nom de l'utilisateur a supprimer");
      commonname = saisieString();
      System.out.println(ldaputils.getUIDFromSubject("CN="+commonname.replace(" ", "-") + " " + surname.replace(" ", "-")));
      String uid = "uid="+ldaputils.getUIDFromSubject("CN="+commonname.replace(" ", "-") + " " + surname.replace(" ", "-"));
      ldaputils.deleteUser(uid+";"+ Config.get("USERS_BASE_DN", ""),pass);
      System.out.println("Utilisateur supprimer avec succ�s");
    }
    catch (Exception e)
    {
      System.out.println("Utilisateur inconnu");
      e.printStackTrace();
    }
    
  }

  private static void createClient(String pass)
  {
      String surname,commonname,pwd,uid ;
      System.out.println("Entrez votre nom");
      surname = saisieString();
      System.out.println("Entrez votre pr�nom");
      commonname = saisieString();
      System.out.println("Entrez votre mot de passe");
      pwd = saisieString();
      
      uid = String.valueOf(System.currentTimeMillis());
      try
      {
        ldaputils.createNewUser(uid, commonname.replace(" ", "-"), surname.replace(" ", "-"), MessageDigestUtils.digest(pwd),pass);
        System.out.println("Utilisateur ajout� avec succ�s");
      }
      catch (IOException e)
      {
        System.out.println("erreur lors de l'ajout d'un client");
        e.printStackTrace();
      }
  }

  private static char saisie()
  {
    char io = ' ';
    Scanner sc = new Scanner(System.in);
    io = sc.next().charAt(0);
    return io;
  }
  
  private static String saisieString()
  {
    Scanner sc = new Scanner(System.in);
    String s = null;
    s = sc.nextLine();
    return s;
  }
}
