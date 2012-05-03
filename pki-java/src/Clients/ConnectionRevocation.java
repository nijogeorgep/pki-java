package Clients;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoAPI.CRLManager;
import CryptoAPI.MessageDigestUtils;
import Ldap.ldaputils;

public class ConnectionRevocation extends Connection
{

  public ConnectionRevocation(String ip, Integer port)
  {
    super(ip, port);
  }

  public void run()
  {
    Security.addProvider(new BouncyCastleProvider());

   // System.out.println(CRLManager.CRLFromCrlHolder(ldaputils.getCRL("ou=rootCA,dc=pkirepository,dc=org","intermediatePeopleCA")));
    
    //System.exit(0);
    
    String surname,commonname,pwd;
    System.out.println("Entrez votre nom");
    surname = ClientUtils.saisieString();
    System.out.println("Entrez votre prenom");
    commonname = ClientUtils.saisieString();
    System.out.println("Entrez votre mot de passe");
    pwd = ClientUtils.saisieString();
    String identite = commonname.replace(" ", "-") + " " + surname.replace(" ", "-");
    
    String uid = ldaputils.getUIDFromSubject(identite);

    try
    {
      out.write(uid.getBytes()); //on envoie la requete
      
      String reply  = new String(this.read(in));
      //System.out.println(new String(reply));
      out.write(MessageDigestUtils.digest(pwd));
      
      byte[] rep = this.read(in);
      String res  = new String(rep);
      System.out.println(res.toString());
      s.close();
    }
    catch (IOException e)
    {
      e.printStackTrace();
    } 
   
    
  }

  
  public static byte[] read(InputStream in) throws IOException {
    byte[] res = new byte[4096]; //Créer un tableau très grand. (Je m'attends a tout recevoir d'un coup j'ai pas envie de me faire chier)
    int read = in.read(res); //Je lis
    if (read == -1) { //si on a rien lu c'est que le serveur a eu un problème
        throw new IOException();
    }
    
    byte[] res_fitted = new byte[read]; //je déclare un tableau de la taille juste
    for (int i=0; i < read; i++) { //je recopie le byte dedans
      res_fitted[i] = res[i];
    }
    return res_fitted;
  }
}
