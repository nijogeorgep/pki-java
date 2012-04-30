package Useless;

/*
 * ComClass.java
 *
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */


import java.security.spec.RSAPublicKeySpec;
import java.util.ListIterator;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Logger;
import javax.crypto.*;
import java.security.*;
import java.util.Hashtable;
import javax.crypto.spec.*;
import java.security.spec.X509EncodedKeySpec;

public abstract class ComClass extends Thread
{
  Network e;
  int receivedNum = 0;
  public static Logger theLogger = Logger.getLogger(ComClass.class.getName());
  private Cipher ecipher;
  private Cipher dcipher;
  public Hashtable<String, Key> keys = new Hashtable<String, Key>();

  public void shareKey(Key key, String name)
  {
    registerKey(key, name);
  }

  public void registerKey(Key key, String name)
  {
    keys.put(name, key);
  }

  private KeyGenerationClass keyGenClass;

  public KeyPair generateKeyPair(long userseed)
  {
    return keyGenClass.generateKeyPair(userseed);
  }

  public SecretKey generateSharedKey()
  {
    return keyGenClass.generateSharedKey();
  }

  public String generateMessage(String message)
  {
    return message;
  }

  public abstract void processIncoming(Vector<String> v);

  public boolean check(Object a, Object b)
  {
    if (!a.equals(b))
    {
      theLogger.severe("Incoming message did not match expected");
      theLogger
          .info("Expected: " + b.toString() + " Received: " + a.toString());
    }
    return a.equals(b);
  }

  public String sendKey(Key key)
  {
    try
    {
      byte[] keyBytes = key.getEncoded();
      String keyRepresentation = new String(keyBytes, "ISO-8859-1");
      return keyRepresentation;
    }
    catch (Exception e)
    {
      System.out.println(e);
    }
    return null;
  }

  public SecretKey receiveSecretKey(String str)
  {
    try
    {
      byte[] keyBytes = str.getBytes("ISO-8859-1");
      return new SecretKeySpec(keyBytes, "DES");
    }
    catch (Exception e)
    {
      System.out.println(e);
    }
    return null;
  }

  public PublicKey receivePublicKey(String str)
  {
    try
    {
      X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(str
          .getBytes("ISO-8859-1"));
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");

      return keyFactory.generatePublic(pubKeySpec);
    }
    catch (Exception e)
    {
      System.out.println(e);
    }
    return null;

  }

  // TODO: Multiple dest/orig in tool
  public String encrypt(Vector v, Key key, String at, Vector<String> dest)
  {
    return encrypt(v, key);
  }

  public Vector decrypt(String str, Key key, String at, Vector<String> orig)
  {
    return decrypt(str, key);
  }

  public String encrypt(Vector v, Key key, String at, String dest)
  {
    return encrypt(v, key);
  }

  public Vector decrypt(String str, Key key, String at, String orig)
  {
    return decrypt(str, key);
  }

  public String encrypt(Vector v, Key key)
  {
    String message = null;
    ListIterator i = v.listIterator();
    while (i.hasNext())
    {
      String msgPart = (String) i.next();
      if (message == null)
      {
        message = msgPart;
      }
      else
      {
        message = message.concat(msgPart);
      }
      if (i.hasNext())
      {
        message = message.concat("\n");
      }
    }
    try
    {
      ecipher = Cipher.getInstance(key.getAlgorithm());
      ecipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] utf8 = message.getBytes("UTF8");

      // Encrypt
      byte[] enc = ecipher.doFinal(utf8);
      // Encode bytes to base64 to get a string
      return new sun.misc.BASE64Encoder().encode(enc);
    }
    catch (Exception e)
    {
      System.out.println(e);
    }
    /*
     * catch (javax.crypto.NoSuchPaddingException e) {} catch
     * (java.security.NoSuchAlgorithmException e) {} catch
     * (java.security.InvalidKeyException e) {} catch
     * (javax.crypto.BadPaddingException e) {} catch (IllegalBlockSizeException
     * e) {} catch (java.io.UnsupportedEncodingException e) {} catch
     * (java.io.IOException e) {}
     */
    return null;
  }

  public Vector decrypt(String str, Key key)
  {
    try
    {
      dcipher = Cipher.getInstance(key.getAlgorithm());

      dcipher.init(Cipher.DECRYPT_MODE, key);

      // Decode base64 to get bytes
      byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);

      // Decrypt
      byte[] utf8 = dcipher.doFinal(dec);

      // Decode using utf-8
      String parts = new String(utf8, "UTF8");
      StringTokenizer st = new StringTokenizer(parts, "\n");
      Vector v = new Vector();
      while (st.hasMoreTokens())
        v.add(st.nextToken());
      return v;
    }
    /*
     * catch (javax.crypto.NoSuchPaddingException e) {} catch
     * (java.security.NoSuchAlgorithmException e) {} catch
     * (java.security.InvalidKeyException e) {} catch
     * (javax.crypto.BadPaddingException e) {} catch (IllegalBlockSizeException
     * e) {} catch (java.io.UnsupportedEncodingException e) {} catch
     * (java.io.IOException e) {}
     */
    catch (Exception e)
    {
      System.out.println(e);
    }
    return null;
  }

}
