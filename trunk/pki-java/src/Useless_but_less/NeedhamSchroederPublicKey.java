package Useless_but_less;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import Admin.UserManager;
import CryptoAPI.AsymetricKeyManager;
import CryptoAPI.CertificateManager;
import CryptoAPI.MessageDigestUtils;
import CryptoAPI.NeedhamSchroeder;
import Ldap.ldaputils;

public class NeedhamSchroederPublicKey
{
  
  public static BigInteger getUserUid(String nom, String prenom)
  {
    try
    {
      return new BigInteger( ldaputils.getUIDFromSubject(nom+" "+prenom));
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  /*
  public static byte[] cipherCertBWithPrivateKeyS(X509Certificate b, PrivateKey sPrivKey)
  {
    try
    {
      return AsymetricKeyManager.cipher(sPrivKey, b.getEncoded());
    }
    catch (Exception e) 
    {
      e.printStackTrace();
    }
    return null ;
  }

  public static byte[] cipherNonceAWithPublicKeyB(BigInteger nonceA, byte[] encodedDataBCertificate, X509Certificate s)
  {
    try
    {
      X509Certificate certB = CertificateUtils.certificateFromByteArray(AsymetricKeyManager.decipher(s, encodedDataBCertificate));
      return AsymetricKeyManager.cipher(certB, nonceA.toByteArray());
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  */
  public static byte[] cipherNonceANonceBWithPublicKeyA(byte[] dataEncodedNonceA, X509Certificate certA, PrivateKey pkB, BigInteger nonceB)
  {
    try
    {
      byte[] nonceA = AsymetricKeyManager.decipher(pkB, dataEncodedNonceA);
      byte[] nonceBinByte = nonceB.toByteArray();
      byte[] tmp = new byte[nonceA.length+nonceBinByte.length] ;
      for(int i = 0 ; i < nonceA.length; i++)
      {
        tmp[i]=nonceA[i];
      }
      for(int j = nonceA.length ; j < tmp.length ; j++ )
      {
        tmp[j]= nonceBinByte[j-nonceA.length];
      }
      
      return AsymetricKeyManager.cipher(certA, tmp);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] cipherNonceBWithPublicKeyB(byte[] dataEncodedNonceANonceB, BigInteger nonceA, PrivateKey pkA, X509Certificate certB)
  {
    try
    {
       byte[] noncesAB = AsymetricKeyManager.decipher(pkA, dataEncodedNonceANonceB);
       int tailleIni = nonceA.toByteArray().length;
       
       byte[] tmp = new byte[tailleIni];
       for(int i = 0 ; i < tailleIni ; i++)
       {
         tmp[i]=noncesAB[i];
       }
       if( nonceA.equals(new BigInteger(tmp)))
       {
         tmp = new byte[noncesAB.length-tailleIni];
         for(int j = tailleIni ; j < noncesAB.length ; j++)
         {
           tmp[j-tailleIni] = noncesAB[j];
         }
         return AsymetricKeyManager.cipher(certB, tmp);
       }
       else
       {
         return null ;
       }
    }
    
    catch (Exception e)
    {
      e.printStackTrace();
      return null;
    }
  }
  
  
  public static byte[] generateSessionKey(BigInteger a, BigInteger b)
  {
    byte[] aArray = a.toByteArray();
    byte[] bArray = b.toByteArray();
    
    byte[] tmp = new byte[aArray.length+bArray.length] ;
    for(int i = 0 ; i < aArray.length; i++)
    {
      tmp[i]=aArray[i];
    }
    for(int j = aArray.length ; j < tmp.length ; j++ )
    {
      tmp[j]= bArray[j-aArray.length];
    }
    return MessageDigestUtils.digest(tmp);
  }
  
  public static BigInteger generateNonce()
  {
    Random randomGenerator = new Random();
    return   new BigInteger(53, randomGenerator);
  }
  
  public static void main(String[]args) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException, IOException
  {
    
    BigInteger bigint = NeedhamSchroeder.generateNonce();
    BigInteger bigint2 = NeedhamSchroeder.generateNonce();
    System.out.println(bigint);
    System.out.println(bigint2);

    Security.addProvider(new BouncyCastleProvider());
    KeyPair   kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    KeyPair   kp2 = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    X509Certificate b =  CertificateManager.createSelfSignedCertificate("Coucou toto", kp);
    X509Certificate a =  CertificateManager.createSelfSignedCertificate("Calu tata", kp2);
    /*
    byte[] code = NeedhamSchroeder.firstStep(b, bigint);
    
    System.out.println("fin step one " + new BigInteger(code));
    
    byte[] decode = NeedhamSchroeder.secondStep(bigint2, code, b, a, kp.getPrivate());
    
    System.out.println("fin step two " + new BigInteger(decode));
    
    byte[] last = NeedhamSchroeder.thirdStep(decode, b, a, bigint, kp2.getPrivate());
    */
   
  }

}
