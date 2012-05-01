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
  
  public static byte[] sCryptKeyB(X509Certificate b, PrivateKey sPrivKey, BigInteger nonce)
  {
    try
    {
      return AsymetricKeyManager.sign(sPrivKey, b.getEncoded());
    }
    catch (Exception e) 
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] aCryptNonceA(BigInteger nonce, byte[] dataBCertificate)
  {
    try
    {
      X509Certificate certB = CertificateUtils.certificateFromByteArray(dataBCertificate);
      return AsymetricKeyManager.cipher(certB, nonce.toByteArray());
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] bCryptNonceA(BigInteger nonceA, byte[] dataAcertificate)
  {
    try
    {
      X509Certificate certA = CertificateUtils.certificateFromByteArray(dataAcertificate);
      return AsymetricKeyManager.cipher(certA, nonceA.toByteArray());
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] aCryptNonceB(byte[] toEncodeNonceB, byte[] dataBCertificate)
  {
    try
    {
      X509Certificate certB = CertificateUtils.certificateFromByteArray(dataBCertificate);
      return AsymetricKeyManager.cipher(certB, toEncodeNonceB);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static void main(String[] args)
  {

  }

}
