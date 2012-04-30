package Utils;

import java.io.IOException;
import java.util.Scanner;

import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;

public class ClientManager
{
  public static void main(String[]args)
  {
    System.out.println(new String(ldaputils.getUserPassword("1234"))); 
    System.out.println(new String(MessageDigestUtils.digest("coucou")));
    System.out.println(MessageDigestUtils.checkDigest(MessageDigestUtils.digest("coucou"),new String(ldaputils.getUserPassword("1234")).getBytes() ));
   
    
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
        case('1'): createClient();
          break;
        case('2'): deleteClient();
          break;
      }
          
    } while(!(al=='q'));
   
  }
  
  private static void deleteClient()
  {
    try
    {
      String surname, commonname;
      System.out.println("Entrez le nom de l'utilisateur a supprimer");
      surname = saisieString();
      System.out.println("Entrez le prénom de l'utilisateur a supprimer");
      commonname = saisieString();
      System.out.println(ldaputils.getUIDFromSubject("CN="+commonname.replace(" ", "-") + " " + surname.replace(" ", "-")));
      ldaputils.deleteUser("uid="+ldaputils.getUIDFromSubject("CN="+commonname.replace(" ", "-") + " " + surname.replace(" ", "-"))+";"+ Config.get("USERS_BASE_DN", ""));
      System.out.println("Utilisateur supprimer avec succès");
    }
    catch (IOException e)
    {
      System.out.println("Utilisateur inconnu");
      e.printStackTrace();
    }
    
  }

  private static void createClient()
  {
      String surname,commonname,pwd,uid ;
      System.out.println("Entrez votre nom");
      surname = saisieString();
      System.out.println("Entrez votre prénom");
      commonname = saisieString();
      System.out.println("Entrez votre mot de passe");
      pwd = saisieString();
      
      uid = String.valueOf(System.currentTimeMillis());
      try
      {
        ldaputils.createNewUser(uid, commonname.replace(" ", "-"), surname.replace(" ", "-"), MessageDigestUtils.digest(pwd));
        System.out.println("Utilisateur ajouté avec succès");
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
