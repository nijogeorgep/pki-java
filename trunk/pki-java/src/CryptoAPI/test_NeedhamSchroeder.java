package CryptoAPI;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

public class test_NeedhamSchroeder
{
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
    
    byte[] code = NeedhamSchroeder.firstStep(b, bigint);
    
    System.out.println("fin step one " + new BigInteger(code));
    
    byte[] decode = NeedhamSchroeder.secondStep(bigint2, code, b, a, kp.getPrivate());
    
    System.out.println("fin step two " + new BigInteger(decode));
    
    byte[] last = NeedhamSchroeder.thirdStep(decode, b, a, bigint, kp2.getPrivate());
  }
}
