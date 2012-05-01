package CryptoAPI;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import Ldap.ldaputils;
import Utils.ClientManager;

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
  
  public static void main(String[] args)
  {

  }

}
