package Useless;

/*
 * NeedhamSchroeder.java
 *
 *
 */
import java.util.Vector;
import javax.crypto.*;


public class NeedhamSchroeder extends KeyGenerationClass
{
  public static void main(String[] args)
  {
    Network net = new Network();
    A a = new A(net);
    net.register("A", a);
    B b = new B(net);
    net.register("B", b);
    S s = new S(net);
    net.register("S", s);

    SecretKey keyA = generateSharedKey();
    SecretKey keyB = generateSharedKey();
    SecretKey succ = generateSharedKey();

    a.shareKey(keyA, "KAS");
    s.shareKey(keyA, "KAS");

    b.shareKey(keyB, "KBS");
    s.shareKey(keyB, "KBS");

    a.shareKey(succ, "SUCC");
    b.shareKey(succ, "SUCC");
    s.shareKey(succ, "SUCC");

    a.start();
    b.start();
    s.start();
  }
}

class A extends ComClass
{
  Network net;
  String nonceA;

  public A(Network net)
  {
    this.net = net;
  }

  public void run()
  {
    Vector v = new Vector();
    v.add("A");
    v.add("B");
    String nonceA = generateMessage("nonce");
    v.add(nonceA);
    net.send(this, "S", v);

  }

  public void processIncoming(Vector<String> v)
  {
    switch (receivedNum)
    {
      case 0:
        receivedNum++;
        // check first
        assert check(v.elementAt(0), "S");
        // check second
        assert check(v.elementAt(1), "A");
        String msgtoBeDecoded = v.elementAt(2);
        SecretKey keyS = (SecretKey) keys.get("KAS");
        Vector<String> decode = decrypt(msgtoBeDecoded, keyS);

        assert check(decode.elementAt(0), nonceA);
        assert check(decode.elementAt(1), "B");
        SecretKey keyAB = receiveSecretKey(decode.elementAt(2));
        registerKey(keyAB, "K");
        String encryptedMsgToB = decode.elementAt(3);

        Vector vToB1 = new Vector();
        vToB1.add(encryptedMsgToB);
        net.send(this, "B", vToB1);
        break;
      case 1:
        receivedNum++;
        // check first
        assert check(v.elementAt(0), "B");
        // check second
        assert check(v.elementAt(1), "A");
        String msgtoBeDecoded2 = v.elementAt(2);
        SecretKey keyAB2 = (SecretKey) keys.get("K");
        Vector<String> decode2 = decrypt(msgtoBeDecoded2, keyAB2);
        String nonceB = decode2.elementAt(0);

        Vector vToB2Enc = new Vector();
        Vector vToB2 = new Vector();
        SecretKey succ = (SecretKey) keys.get("SUCC");
        Vector vToBNonce = new Vector();
        vToBNonce.add(nonceB);
        vToB2Enc.add(encrypt(vToBNonce, succ));
        vToB2.add(encrypt(vToB2Enc, keyAB2));
        net.send(this, "B", vToB2);

        String msg1 = generateMessage("FIRST BIT OF MESSAGE");
        String msg2 = generateMessage("SECOND BIT OF MESSAGE");
        Vector vToB3Enc = new Vector();
        Vector vToB3 = new Vector();
        vToB3Enc.add(msg1);
        vToB3Enc.add(msg2);
        vToB3.add(encrypt(vToB3Enc, keyAB2));
        net.send(this, "B", vToB3);
    }
  }

}

class B extends ComClass
{
  Network net;
  String nonceBstore;

  public B(Network net)
  {
    this.net = net;
  }

  public void processIncoming(Vector<String> v)
  {
    switch (receivedNum)
    {
      case 0:
        receivedNum++;
        // check first
        assert check(v.elementAt(0), "A");
        // check second
        assert check(v.elementAt(1), "B");
        // check third
        // assign fourth
        SecretKey key = (SecretKey) keys.get("KBS");
        String msgToBeDecoded = v.elementAt(2);
        Vector<String> decode = decrypt(msgToBeDecoded, key);

        SecretKey keyAB = receiveSecretKey(decode.elementAt(0));
        String source = decode.elementAt(1);
        registerKey(keyAB, "KAB");

        Vector vToAEnc = new Vector();
        String nonceB = generateMessage("nonceB");
        nonceBstore = nonceB;
        vToAEnc.add(nonceB);
        Vector vToA = new Vector();
        vToA.add(encrypt(vToAEnc, keyAB));
        net.send(this, "A", vToA);

        break;
      case 1:
        receivedNum++;
        // check first
        assert check(v.elementAt(0), "A");
        // check second
        assert check(v.elementAt(1), "B");
        String msgToBeDecoded2 = v.elementAt(2);
        SecretKey key2 = (SecretKey) keys.get("KAB");

        Vector<String> decode2 = decrypt(msgToBeDecoded2, key2);

        SecretKey succ = (SecretKey) keys.get("SUCC");
        Vector vNonce = new Vector();
        nonceB = nonceBstore;
        vNonce.add(nonceB);

        assert check(decode2.elementAt(0), encrypt(vNonce, succ));
        break;
      case 2:
        receivedNum++;
        // check first
        assert check(v.elementAt(0), "A");
        // check second
        assert check(v.elementAt(1), "B");
        String msgToBeDecoded3 = v.elementAt(2);
        SecretKey key3 = (SecretKey) keys.get("KAB");

        Vector<String> decode3 = decrypt(msgToBeDecoded3, key3);
        String msg1 = decode3.elementAt(0);
        String msg2 = decode3.elementAt(1);
        theLogger.info(msg1);
        theLogger.info(msg2);
    }

  }
}

class S extends ComClass
{
  Network e;

  public S(Network e)
  {
    this.e = e;
  }

  public void processIncoming(Vector<String> v)
  {
    switch (receivedNum)
    {
      case 0:
        receivedNum++;
        // check first
        assert check(v.elementAt(0), "A");
        // check second
        assert check(v.elementAt(1), "S");

        assert check(v.elementAt(2), "A");

        String destination = v.elementAt(3);
        String nonce = v.elementAt(4);

        SecretKey keyA = (SecretKey) keys.get("KAS");
        SecretKey keyB = (SecretKey) keys.get("KBS");

        Vector vToAEncrypted = new Vector();
        vToAEncrypted.add(nonce);
        vToAEncrypted.add(destination);
        SecretKey key = generateSharedKey();
        registerKey(key, "K");
        vToAEncrypted.add(sendKey(key));
        Vector vToBEncrypted = new Vector();
        vToBEncrypted.add(sendKey(key));
        vToBEncrypted.add("A");
        vToAEncrypted.add(encrypt(vToBEncrypted, keyB));

        Vector vToA = new Vector();
        vToA.add(encrypt(vToAEncrypted, keyA));
        e.send(this, "A", vToA);

        break;
    }
  }
}