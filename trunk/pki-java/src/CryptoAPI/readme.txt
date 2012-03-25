Voici quelques infos concernant la cryptoAPI

Je pensais la faire car ça permet de faire une bonne couche d'abstraction entre les servers etc et la crypto elle-même.
(Et donc sa peut permettre de la réutiliser dans d'autres projets bref).

A noter que tout mettre là permettras à toutes les entitées du PKI d'utiliser les fonctions cryptographiques et ainsi éviter toute redondance de code.

!!
D'ailleur sa me fait penser à un truc qui à rien à voir mais y a beaucoup de redondance de code de server parmis toutes les entitées.
On pourraisfaire genre une superclasse Server et toutes les classes filles devrais implementer une methode "processClientRead" qui s'occuperais de gérer chaques messages
reçus par les clients.
Ainsi tout les serveurs auraient le même code de serveur mais tous géreraient les message entrant différements.

Idem pour l'écriture.

Non ??
!!

Voici quelques classes qui pourrait être interessant de coder :

		- KeyStoreManager (dans le cas ou l'utilisation du KeyStore ne soit pas aisée)
		- RSAManager: Qui s'occuperais de chiffrer, déchiffer des messages (avec une string données), faire de la vérification de signature etc..
		- CertificatHelper: Qui permettrait de retrouver facilement certains champs d'un certificat, calculer si la certificate chain et ok etc..
		- OCSPManager: Qui permettrais de créer des requetes, analyses le résultat d'une réponse etc.
		- CRLManager: Qui s'occuperais par example de savoir si un certificat est dans une liste, savoir de quand date la dernière liste téléchargée pour un certificat donnée etc..