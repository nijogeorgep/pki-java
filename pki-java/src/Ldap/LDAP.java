package Ldap;

import java.util.Enumeration;
import java.util.Hashtable;

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
	 *  Connect to the ldap as Anonymous
	 */
		Hashtable<String,String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, url);

		ctx = new InitialDirContext(env);

	}
	
	public DirContext getContext() {
		return ctx;
	}
	
	public void initAuth(String url, String principal, String credential) throws NamingException {
	/*
	 * Connect to the LDAP using the credentials given in parameters
	 */
		Hashtable<String,String> env = new Hashtable<String, String>(11);
		env.put(Context.INITIAL_CONTEXT_FACTORY,  "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, url);
		
		env.put(Context.SECURITY_AUTHENTICATION, "simple"); //don't allow another choices
		env.put(Context.SECURITY_PRINCIPAL, principal);
		env.put(Context.SECURITY_CREDENTIALS,credential);

		ctx = new InitialDirContext(env);

	}
	
	public boolean close() throws NamingException {
	/*
	 * Close the LDAP Connection
	 */
		ctx.close();
		return true;
	}
	
	public void searchAllAttributs(String dn, String attid, String value) throws NamingException {
	/*
	 * Print all the attributes of the given request
	 */
	    Attributes matchAttrs = new BasicAttributes(true); // ignore case
	    matchAttrs.put(new BasicAttribute(attid, value));
	    NamingEnumeration<SearchResult> answer;

	    answer = ctx.search(dn, matchAttrs);

	    // Print the answer
	    while (answer.hasMore()) {
	        SearchResult sr = (SearchResult)answer.next();
	        System.out.println(">>>" + sr.getName());
	        Enumeration<? extends Attribute> att = sr.getAttributes().getAll();
	        while(att.hasMoreElements()) {
	        	Attribute at = (Attribute) att.nextElement();
	        	System.out.println(at);
	        }
	    }
	}
	
	public Object getAttribute(String dnBase, String filter, String att) throws NamingException {
		/*
		 * Return the attribute required in argument.
		 * Return an Object because the object is either a String either a byte[]
		 */
		DirContext o = (DirContext) ctx.lookup(filter+"," + dnBase);
	      Attributes attributes = o.getAttributes("");
	      return attributes.get(att).get();
	}
	
	
	public void searchAttribute(String dnBase, String filter, String att) throws NamingException {
	/*
	 * Print attribute for every entries that match the given filter
	 */
		SearchControls constraints = new SearchControls(); // Research options
		constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

		//Give the base DN and the filter
		NamingEnumeration<SearchResult> results = ctx.search(dnBase, filter,	constraints);

		//For each entries print the attributes
		while (results != null && results.hasMore()) {
			SearchResult entry = (SearchResult) results.next(); // Read the entry

			Attributes attrs = entry.getAttributes();
			if (attrs != null) {
				//Loop through all attributes
				for (NamingEnumeration<? extends Attribute> attEnum = attrs.getAll(); attEnum.hasMoreElements();) {
					Attribute attr = (Attribute) attEnum.next();
					String attrId = attr.getID();
					if (attrId.equals(att)) { // If the attribute is equal to the one we are looking for
						Enumeration<?> vals = attr.getAll();
						vals.hasMoreElements();
						System.out.println (vals.nextElement().toString()); // Print only the first value of the attribute
					}
				}
			}
		}
	}
	
	public String searchAttribute(String dnBase, String cn, String sn, String att) throws NamingException {
	/*
	 * Same as the one above put return the attribute
	 */
		SearchControls constraints = new SearchControls();
		constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration<SearchResult> results = ctx.search(dnBase, sn, constraints);

		while (results != null && results.hasMore()) {
			SearchResult entry = (SearchResult) results.next();

			Attributes attrs = entry.getAttributes();
			if (attrs != null) {
				String uid = "";
				for (NamingEnumeration<? extends Attribute> attEnum = attrs.getAll(); attEnum
						.hasMoreElements();) {
					Attribute attr = (Attribute) attEnum.next();
					String attrId = attr.getID();

					if (attrId.equals(att)) {
						Enumeration<?> valsInterm = attr.getAll();
						valsInterm.hasMoreElements();
						uid = valsInterm.nextElement().toString();
					}
					if (attrId.equals("cn")) {
						Enumeration<?> valsInterm = attr.getAll();
						valsInterm.hasMoreElements();
						if (valsInterm.nextElement().toString().equals(cn)) {
							return uid;
						}
					}
				}
			}
		}
		return null;
	}

	public void modifAttribute(int operation,String dnBase, String attName, Object value) throws NamingException {
        Attributes attributes = new BasicAttributes(true); 
        Attribute attribut = new BasicAttribute(attName); 
        if(value != null)
        	attribut.add(value); 
        attributes.put(attribut); 

        ctx.modifyAttributes(dnBase, operation, attributes); //ADD REMOVE_ATTRIBUTE, REPLACE_ATTRIBUTE
	}
	
	public void modifMultiples(int operation, String dnBase, Hashtable<String,String> atts) throws NamingException {
		/*
		 * Allow to modify multiples attributes
		 */
		
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
	
	public void deleteObject(String dn) throws NamingException {
		ctx.unbind(dn);
	}

}
