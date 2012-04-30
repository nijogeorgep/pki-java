/*
 * Exo2.java
 *
 * Created on 29 f�vrier 2012, 09:32
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package Useless;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Exo2verify {
    
    /** Creates a new instance of Exo2 */
    public Exo2verify() {
    }
    
    public static String readFile(String name) throws IOException {
        FileInputStream fr = new FileInputStream(name);
        String s = "";
        byte[] buff = new byte[1];
        int read = fr.read(buff);
        while(read != -1) {
            String news = new String(buff);
            s = s.concat(news);
            read = fr.read(buff);
        }
        fr.close();
        return s;
    }
    
    
    public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidKeySpecException, ClassNotFoundException {
        // TODO code application logic here
        Security.addProvider(new BouncyCastleProvider());
        
        ObjectInputStream objinput = new ObjectInputStream(new FileInputStream("modulus.txt"));
        BigInteger mod = (BigInteger) objinput.readObject();
 
        
        objinput = new ObjectInputStream(new FileInputStream("exponent.txt"));
        BigInteger exp = (BigInteger) objinput.readObject();

        System.out.println("Mod :"+mod);
        System.out.println("Exp :"+exp);
        
        RSAPublicKeySpec spec = new RSAPublicKeySpec(mod,exp);
        KeyFactory fac = KeyFactory.getInstance("RSA");
        PublicKey pubkey = fac.generatePublic(spec);
        
        System.out.println("Key:"+pubkey.toString());
        
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initVerify(pubkey); //ou initVerify avec pubkey
        
        String s = readFile("outputsigned.txt");
        
        sig.update(s.getBytes());
    
        String signature = readFile("signature.txt");

        if(sig.verify(pubkey.getEncoded()))
            System.out.println("OK !");
        else
            System.out.println("NOP");

    }
}
