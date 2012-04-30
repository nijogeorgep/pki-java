/*
 * Exo2.java
 *
 * Created on 29 f�vrier 2012, 09:32
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package Useless;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author d21105699
 */
public class Exo2sign {
    
    /** Creates a new instance of Exo2 */
    public Exo2sign() {
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
    /*
        File file_to_sign = new File("fichier_a_signer.txt");
		byte[] buffer = new byte[(int)file_to_sign.length()];
		DataInputStream in = new DataInputStream(new FileInputStream(file_to_sign));
		in.readFully(buffer);
		in.close();
		
     */
    
    public static void main(String[] args) throws FileNotFoundException, NoSuchAlgorithmException, IOException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidKeySpecException {
        // TODO code application logic here
        Security.addProvider(new BouncyCastleProvider());
        
        Scanner sc = new Scanner(System.in);
        String s = sc.nextLine();
        
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        KeyPair keys = keygen.generateKeyPair();
        PrivateKey privkey = keys.getPrivate();
        PublicKey pubkey = keys.getPublic();
        
        
        Signature sig = Signature.getInstance("SHA1withRSA");
        sig.initSign(privkey); //ou initVerify avec pubkey
        
        sig.update(s.getBytes());
        byte[] res = sig.sign();

        FileOutputStream out = new FileOutputStream("outputsigned.txt");
        out.write(s.getBytes());
        //ajout de  la signature
        out.close();
        
        out = new FileOutputStream("signature.txt");
        out.write(res);
        out.close();
        
        
        KeyFactory fac = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec spec = fac.getKeySpec(pubkey, RSAPublicKeySpec.class);
        BigInteger mod = spec.getModulus();
        BigInteger exp = spec.getPublicExponent();
        
        ObjectOutputStream objstream = new ObjectOutputStream(new FileOutputStream("modulus.txt"));
        objstream.writeObject(mod);
        objstream.close();

        objstream = new ObjectOutputStream(new FileOutputStream("exponent.txt"));
        objstream.writeObject(exp);
        objstream.close();

        System.out.println("Key:"+pubkey.toString());
        System.out.println("Mod :"+mod);
        System.out.println("Exp :"+exp);
        
        out = new FileOutputStream("privkey.txt");
        out.write(pubkey.getEncoded());
        out.close();
        
        s = sc.nextLine();
    }
}
