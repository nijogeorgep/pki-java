package CryptoAPI;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class NeedhamSchroeder
{
  
  public static byte[] firstStep(X509Certificate b, BigInteger nonce)
  {
    try
    {
      byte[] aEncodeNonce = nonce.toByteArray();
      return AsymetricKeyManager.cipher(b, aEncodeNonce);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] secondStep(BigInteger nonce, byte[] nonceEncoded, X509Certificate b, X509Certificate a, PrivateKey bPriv )
  {
    try
    {
      byte[] dec  = AsymetricKeyManager.decipher(bPriv, nonceEncoded);
      
      byte[] tmp = new byte[dec.length+nonce.toByteArray().length] ;
      for(int i = 0 ; i < dec.length; i++)
      {
        tmp[i]=dec[i];
      }
      for(int j = dec.length ; j < tmp.length ; j++ )
      {
        tmp[j]= nonce.toByteArray()[j-dec.length];
      }
      return AsymetricKeyManager.cipher(a, tmp);
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] thirdStep(byte[] data, X509Certificate b, X509Certificate a, BigInteger nonceIni, PrivateKey aPriv) 
  {
    try
    {
      byte[] dec = AsymetricKeyManager.decipher(aPriv, data);
      int tailleIni = nonceIni.toByteArray().length;
      byte[] tmp = new byte[tailleIni];
      
      for(int i = 0 ; i < tailleIni ; i++)
      {
        tmp[i]=dec[i];
      }
      
      if( nonceIni.equals(new BigInteger(tmp)))
      {
        tmp = new byte[dec.length-tailleIni];
        for(int j = tailleIni ; j < dec.length ; j++)
        {
          tmp[j-tailleIni] = dec[j];
        }
        return AsymetricKeyManager.cipher(b, tmp);
      }
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static BigInteger generateNonce()
  {
    Random randomGenerator = new Random();
    return   new BigInteger(53, randomGenerator);
  }
}
