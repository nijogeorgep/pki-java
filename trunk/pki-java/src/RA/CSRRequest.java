package RA;

public class CSRRequest {
	/* ######## README #########
	 * (Lire d'abord RevocationRequest)
	 * Le fonctionnement est similaire a RevocationRequest sauf qu'il ne fait pas la même chose:
	 * Il lance aussi un thread autonome qui fait:
	 * 			- Vérifie l'identité de la personne qui fait la demande (normalement sa se fait avec des NSS etc) mais la on va juste supposer que la personne existe dans le LDAP.
	 * 			- Si la personne n'existe pas le demande de certificat est refusé et le thread s'arrete là (passe son status à refusé)
	 * 			- Si la personne existe on considère la demande de certificat comme valide et on se connecte au RA pour la faire signer.
	 * 			- On crée le certificat a partir de la CSR signé que le CA nous a renvoyé
	 * 			- On se connecte au repository pour envoyer le certificat
	 * 			- On passe le status a OK
	 *########################*/
}
