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
  static Cipher lucipher ;
  static Cipher calcipher;
  /*
   * etape1
   * -genere une nonce avec en param la clé publique de B la crypte et
   * (return byte array)
   * 
   * etape 2
   * b vers a, prend en param un bytearray + la clé privé de B, la clé publique de A
   * ac clé déchiffre le bytearray et recup la nonce
   * puis genere une nonce B
   *et chiffre ces deux nonces la avec la clé publique de A
   *renvoi un bytearray
   *
   *etape3
   *prends un bytearray en param + clé publique de b, clé privé de a, nonce etape1 de a
   *déchiffre ac privé le bytearray
   *vérifie que la nonce de a ici est la même que celle de l'étape 1
   *si egal, rechiffre la nonce b avec la clé b et renvoi le bytearray
   */
  
  public static byte[] firstStep(X509Certificate b, BigInteger nonce)
  {
    try
    {
      lucipher = Cipher.getInstance(b.getPublicKey().getAlgorithm());
      lucipher.init(Cipher.ENCRYPT_MODE, b.getPublicKey());
      byte[] aEncodeNonce = nonce.toByteArray();
      byte[] enc = lucipher.doFinal(aEncodeNonce);
      return enc;
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
      calcipher = Cipher.getInstance(b.getPublicKey().getAlgorithm());
      calcipher.init(Cipher.DECRYPT_MODE, bPriv );
      lucipher = Cipher.getInstance(a.getPublicKey().getAlgorithm());
      lucipher.init(Cipher.ENCRYPT_MODE, a.getPublicKey());
      
      byte[] dec  = calcipher.doFinal(nonceEncoded);
      byte[] nonceA = nonce.toByteArray();
      
      byte[] tmp = new byte[dec.length+nonceA.length] ;
      for(int i = 0 ; i < dec.length; i++)
      {
        tmp[i]=dec[i];
      }
      for(int j = dec.length ; j < tmp.length ; j++ )
      {
        tmp[j]= nonceA[j-dec.length];
      }
      
      byte[] enc = lucipher.doFinal(tmp);
      return enc;
      
    }
    catch (Exception e)
    {
      e.printStackTrace();
    }
    return null ;
  }
  
  public static byte[] thirdStep(byte[] nonce, X509Certificate b, X509Certificate a, BigInteger nonceIni, PrivateKey aPriv) 
  {
    try
    {
      calcipher = Cipher.getInstance(a.getPublicKey().getAlgorithm());
      calcipher.init(Cipher.DECRYPT_MODE, aPriv );
      lucipher = Cipher.getInstance(b.getPublicKey().getAlgorithm());
      lucipher.init(Cipher.ENCRYPT_MODE, b.getPublicKey());
      
      byte[] dec  = calcipher.doFinal(nonce);
      
      int tailleIni = nonceIni.toByteArray().length;
      byte[] tmp = new byte[tailleIni];
      
      for(int i = 0 ; i < tmp.length ; i++)
      {
        tmp[i]=nonce[i];
      }
     System.out.println("taille ini " + tailleIni + "    vs taille tmp " +tmp.length ); 
      System.out.println("nonce ini décodé " + new BigInteger(tmp));
      
      if( nonceIni.equals(new BigInteger(tmp)))
      {
        tmp = new byte[nonce.length-tailleIni];
        for(int j = tailleIni ; j < nonce.length ; j++)
        {
          tmp[j-tailleIni] = nonce[j];
        }
        System.out.println("nonce 2 décodé " + new BigInteger(dec));
        byte[] enc = lucipher.doFinal(tmp);
        return enc;
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
