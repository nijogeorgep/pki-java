package Useless;


import java.util.ListIterator;
import java.util.Vector;
import java.util.Hashtable;
import javax.crypto.*;
import java.security.*;
import java.util.Set;
import java.util.Iterator;

public class Network
{
  private Hashtable<String, ComClass> classNameToClass;
  private Hashtable<ComClass, String> classToClassName;

  public Network()
  {
    classNameToClass = new Hashtable<String, ComClass>();
    classToClassName = new Hashtable<ComClass, String>();
  }

  public void send(ComClass source, String dest, Vector tuple)
  {
    ComClass destClass = classNameToClass.get(dest);
    tuple.add(0, classToClassName.get(source));
    tuple.add(1, dest);
    destClass.processIncoming(tuple);
  }

  public void register(String name, ComClass comClass)
  {
    classNameToClass.put(name, comClass);
    classToClassName.put(comClass, name);
  }

  public void shareKey(Key key, String name)
  {
    Set<ComClass> classes = classToClassName.keySet();
    Iterator<ComClass> i = classes.iterator();
    while (i.hasNext())
    {
      ComClass comClass = i.next();
      comClass.shareKey(key, name);
    }
  }
}