package Useless;


import com.sun.org.apache.regexp.internal.StreamCharacterIterator;
import javax.crypto.*;
import java.security.*;

import java.security.spec.X509EncodedKeySpec;

public class KeyGenerationClass
{
  public static KeyPair generateKeyPair(long userseed)
  {
    try
    {

      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
      random.setSeed(userseed);
      keyGen.initialize(1024, random);
      KeyPair keypair = keyGen.genKeyPair();
      return keypair;

    }
    catch (Exception e)
    {
      System.out.println("OO" + e);
    }
    return null;
  }

  public static SecretKey generateSharedKey()
  {
    try
    {
      SecretKey key = KeyGenerator.getInstance("DES").generateKey();
      return key;
    }
    catch (java.security.NoSuchAlgorithmException e)
    {
      System.out.println(e);
    }
    return null;
  }
}
