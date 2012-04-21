package Playground;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Hashtable;

import javax.naming.Binding;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;


public class LDAP {

	DirContext ctx;
	
	public LDAP() { }
	
	public void init(String url) throws NamingException {
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, url);

		ctx = new InitialDirContext(env);

	}
	
	public void initAuth(String url, String principal, String credential) throws NamingException {
		Hashtable env = new Hashtable(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, url);
		
		env.put(Context.SECURITY_AUTHENTICATION, "simple"); //don't allow another choices
		env.put(Context.SECURITY_PRINCIPAL, principal);
		env.put(Context.SECURITY_CREDENTIALS,credential);

		ctx = new InitialDirContext(env);

	}
	
	public boolean close() throws NamingException {
		ctx.close();
		return true;
	}
	
	public void searchAllAttributs(String dn, String attid, String value) throws NamingException {
	    Attributes matchAttrs = new BasicAttributes(true); // ignore case
	    matchAttrs.put(new BasicAttribute(attid, value));
	    NamingEnumeration answer;

	    answer = ctx.search(dn, matchAttrs);

	    // Print the answer
	    while (answer.hasMore()) {
	        SearchResult sr = (SearchResult)answer.next();
	        System.out.println(">>>" + sr.getName());
	        Enumeration att = sr.getAttributes().getAll();
	        while(att.hasMoreElements()) {
	        	Attribute at = (Attribute) att.nextElement();
	        	System.out.println(at);
	        }
	    }
	}
	
	public void searchAttribute(String dnBase, String filter, String att) throws NamingException {
		//Options de recherche
		SearchControls constraints = new SearchControls();
		constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

		//Indication du DN de la base et du filtre de recherche
		NamingEnumeration results = ctx.search(dnBase, filter,	constraints);

		//Pour chaque entrée, afficher les attributs
		while (results != null && results.hasMore()) {
			//Lecture d'une entrée
			SearchResult entry = (SearchResult) results.next();

			Attributes attrs = entry.getAttributes();
			if (attrs != null) {
				//Parcours de tous les attributs
				for (NamingEnumeration attEnum = attrs.getAll(); attEnum.hasMoreElements();) {
					Attribute attr = (Attribute) attEnum.next();
					String attrId = attr.getID();
					if (attrId.equals(att)) {
						Enumeration vals = attr.getAll();
						vals.hasMoreElements();
						// Retour de la première valeur de l'attribut
						System.out.println (vals.nextElement().toString());
					}
				}
			}
		}
	}
	
	public void addObject() throws NamingException {
	      //Apartment objet = new Apartment("12","valeur1");  //L'objet peut être n'importe quel objet qui implémente serializable
	      //ctx.bind("cn=monobject,ou=People,dc=pkirepository,dc=org", objet); 
	}
	
	public void recuObject() throws NamingException {
        String objet = (String) ctx.lookup("cn=monobject,ou=People,dc=pkirepository,dc=org"); 
	}
	
	public void modifAttribute(int operation,String dnBase, String attName, String value) throws NamingException {
        Attributes attributes = new BasicAttributes(true); 
        Attribute attribut = new BasicAttribute(attName); 
        attribut.add(value); 
        attributes.put(attribut); 

        ctx.modifyAttributes(dnBase, operation, attributes); //ADD REMOVE_ATTRIBUTE, REPLACE_ATTRIBUTE
	}
	
	public void modifMultiples(int operation, String dnBase, Hashtable atts) throws NamingException {
		
		ModificationItem[] modifications = new ModificationItem[atts.size()];
		
		int i = 0;
		for (Enumeration<String> enu = atts.keys(); enu.hasMoreElements(); )  {
			String key = enu.nextElement();
			String elt = (String) atts.get(key);
			System.out.println(key+" "+elt);
			Attribute mod = new BasicAttribute(key, elt);
			modifications[i] = new ModificationItem(operation,mod);
			i++;
		}
		
		ctx.modifyAttributes(dnBase, modifications);
	}
	
	public void rename(String oldDn, String newDn) throws NamingException {
		ctx.rename(oldDn,newDn);
	}
	
	public void createNewUser(String dn,String username, String surname, String givenName) throws NamingException {
		      String distinguishedName = "uid=" + username +";"+ dn;
		      Attributes newAttributes = new BasicAttributes(true);
		      Attribute oc = new BasicAttribute("objectclass");
		      oc.add("top");
		      oc.add("person");
		      //oc.add("organizationalperson");
		      //oc.add("user");
		      oc.add("posixAccount");
		      oc.add("shadowAccount");
		      newAttributes.put(oc);
		      newAttributes.put(new BasicAttribute("uidNumber", "3"));
		      newAttributes.put(new BasicAttribute("cn", username));
		      newAttributes.put(new BasicAttribute("sn", surname));
		      newAttributes.put(new BasicAttribute("gidNumber", "2"));
		      newAttributes.put(new BasicAttribute("homeDirectory", "/home/"+username));
		      
		      //newAttributes.put(new BasicAttribute("givenName", givenName));
		      //newAttributes.put(new BasicAttribute("displayName", givenName + " " + surname));
		      System.out.println("Name: " + username + " Attributes: " + newAttributes.toString());
		      ctx.createSubcontext(distinguishedName, newAttributes);
	 }
	
	public void addObject(String dn, Hashtable atts) {
        Attributes attributes = new BasicAttributes();
		int i =0;
        for (Enumeration<String> enu = atts.keys(); enu.hasMoreElements(); )  {
			String key = enu.nextElement();
			String elt = (String) atts.get(key);
	        Attribute attribut = new BasicAttribute(key); 
	        attribut.add(elt); 
	        attributes.put(attribut);
		}
        //ctx.bind(dn, ??, attributes);
	}
	
	public void deleteObject(String dn) throws NamingException {
		ctx.unbind(dn);
	}
	
	public void searchAssoc(String dn) throws NamingException {
		NamingEnumeration e = ctx.listBindings(dn);
		while (e.hasMore()) {
			Binding b = (Binding) e.next();
			
			System.out.println("nom    : " + b.getName());
			System.out.println("objet  : " + b.getObject());
			System.out.println("classe : " + b.getObject().getClass().getName());
		}
	}
	
	public static void main(String[] args) throws NamingException{
		
		LDAP ldap = new LDAP();
		//ldap.init("ldap://localhost:389"); //Could be ldap://localhost:398/ou=People ...
		ldap.initAuth("ldap://87.98.166.65:389","cn=admin,dc=pkirepository,dc=org", "PKICrypto");
		//ldap.searchAllAttributs("ou=People,dc=pkirepository,dc=org", "sn", "Robin");
		//ldap.searchAttribute("ou=People,dc=pkirepository,dc=org", "cn=Robin", "loginShell");//userPassword
		//ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, "uid=robin,ou=People,dc=pkirepository,dc=org", "telephoneNumber", "89.99.99.99.99");
		
		/*
		Hashtable<String , String> h = new Hashtable<String, String>();
		h.put("telephonenumber", "12.34.56.78.90");
		h.put("loginShell","/bin/sh");
		h.put("description","first user");
		ldap.modifMultiples(DirContext.REPLACE_ATTRIBUTE, "uid=robin,ou=People,dc=pkirepository,dc=org",h);
		*/
		
		//ldap.createNewUser("ou=People,dc=pkirepository,dc=org", "Alice", "Durant", "aliiice");
		//ldap.deleteObject("uid=Alice;ou=People,dc=pkirepository,dc=org");
		
		
		//ldap.rename("uid=robin3,ou=People,dc=pkirepository,dc=org","uid=robin,ou=People,dc=pkirepository,dc=org");
		
		ldap.searchAssoc("ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org");
		
		ldap.close();
	}
}
