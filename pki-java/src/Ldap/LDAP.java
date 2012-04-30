package Ldap;

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
	/*
	 *  Se connect a l'url envoyé en paramètre en tant qu' Anonymous
	 */
		Hashtable env = new Hashtable();
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, url);

		ctx = new InitialDirContext(env);

	}
	
	public DirContext getContext() {
		return ctx;
	}
	
	public void initAuth(String url, String principal, String credential) throws NamingException {
	/*
	 * Se connect a l'url LDAP avec le login mot de passe envoyé en paramètre
	 */
		Hashtable env = new Hashtable(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, url);
		
		env.put(Context.SECURITY_AUTHENTICATION, "simple"); //don't allow another choices
		env.put(Context.SECURITY_PRINCIPAL, principal);
		env.put(Context.SECURITY_CREDENTIALS,credential);

		ctx = new InitialDirContext(env);

	}
	
	public boolean close() throws NamingException {
	/*
	 * Ferme la connexion au LDAP
	 */
		ctx.close();
		return true;
	}
	
	public void searchAllAttributs(String dn, String attid, String value) throws NamingException {
	/*
	 * Affiche tout les attributs correspondant à la requete
	 */
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
	
	public Object getAttribute(String dnBase, String filter, String att) throws NamingException {
		DirContext o = (DirContext) ctx.lookup(filter+"," + dnBase);
	      Attributes attributes = o.getAttributes("");
	      return attributes.get(att).get();
	}
	
	
	public void searchAttribute(String dnBase, String filter, String att) throws NamingException {
	/*
	 * Affiche l'attribut demandé pour chaque entrée correspondant au filtre
	 */
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
	
	public String searchAttribute(String dnBase, String cn,String sn, String att) throws NamingException {
	  /*
	   * Affiche l'attribut demandé pour chaque entrée correspondant au filtre
	   */
	    //Options de recherche
	    SearchControls constraints = new SearchControls();
	    constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

	    //Indication du DN de la base et du filtre de recherche
	    NamingEnumeration results = ctx.search(dnBase, sn,  constraints);

	    //Pour chaque entrée, afficher les attributs
	    while (results != null && results.hasMore()) {
	      //Lecture d'une entrée
	      SearchResult entry = (SearchResult) results.next();

	      Attributes attrs = entry.getAttributes();
	      if (attrs != null) {
	        //Parcours de tous les attributs
	        String uid = "";
	        for (NamingEnumeration attEnum = attrs.getAll(); attEnum.hasMoreElements();) {
	          Attribute attr = (Attribute) attEnum.next();
	          String attrId = attr.getID();
	         
	          if(attrId.equals("uid")){
	            Enumeration valsInterm = attr.getAll();
              valsInterm.hasMoreElements();
              uid = valsInterm.nextElement().toString();
	          }
	          if (attrId.equals("cn")) {
	            Enumeration valsInterm = attr.getAll();
	            valsInterm.hasMoreElements();
	            if(valsInterm.nextElement().toString().equals(cn)){
	                return uid;
	              }
	            }
	            }
	          }
	        }
      return null;
	  }
	/*
	public void addObject() throws NamingException {
	      //Apartment objet = new Apartment("12","valeur1");  //L'objet peut être n'importe quel objet qui implémente serializable
	      //ctx.bind("cn=monobject,ou=People,dc=pkirepository,dc=org", objet); 
	}
	
	public void recupObject() throws NamingException {
        String objet = (String) ctx.lookup("cn=monobject,ou=People,dc=pkirepository,dc=org"); 
	}
	*/
	public void modifAttribute(int operation,String dnBase, String attName, Object value) throws NamingException {
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
	/*
	public void searchAssoc(String dn) throws NamingException {
		NamingEnumeration e = ctx.listBindings(dn);
		while (e.hasMore()) {
			Binding b = (Binding) e.next();
			
			System.out.println("nom    : " + b.getName());
			System.out.println("objet  : " + b.getObject());
			System.out.println("classe : " + b.getObject().getClass().getName());
		}
	}
	*/
	
	public static void main(String[] args) throws NamingException{
		
		LDAP ldap = new LDAP();
		//ldap.init("ldap://87.98.166.65:389"); //Could be ldap://localhost:398/ou=People ...
		ldap.initAuth("ldap://87.98.166.65:389","cn=admin,dc=pkirepository,dc=org", "PKICrypto");
		//ldap.searchAllAttributs("ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org", "uid", "1234");
		Object[] tab = {"cn=BOB","sn=David"};
		//ldap.searchAttribute("ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org","cn=BOB", "uid");//userPassword
		ldap.getAttribute("ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org","cn=BOB;sn=David", "uid");
		//ldap.modifAttribute(DirContext.REPLACE_ATTRIBUTE, "uid=1234,ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org", "cn", "BOB");
		
		/*
		Hashtable<String , String> h = new Hashtable<String, String>();
		h.put("description", "nouvelle desc");
		h.put("cn","Robin1");
		h.put("sn","David1");
		ldap.modifMultiples(DirContext.REPLACE_ATTRIBUTE, "uid=robin,ou=People,dc=pkirepository,dc=org",h);
		*/
		
		//ldap.createNewUser("ou=People,dc=pkirepository,dc=org", "Alice", "Durant", "aliiice");
		//ldap.deleteObject("uid=Alice;ou=People,dc=pkirepository,dc=org");
		
		
		//ldap.rename("uid=robin3,ou=People,dc=pkirepository,dc=org","uid=robin,ou=People,dc=pkirepository,dc=org");
		
		//ldap.searchAssoc("ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org");
		//System.out.println(ldap.getAttribute("ou=intermediatePeopleCA,ou=rootCA,dc=pkirepository,dc=org", "uid=1234", "userPassword"));
		
		ldap.close();
	}
}
