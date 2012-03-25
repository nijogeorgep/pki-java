package RA;

public class RevocationRequest {
/* ######## README #########
 * Bon j'explique brievement l'idée qui m'est passé par la tête.
 * Cet objet sera crée pour chaque demande de revocation faite auprès du RA.
 * Concrètement ce quie fait cet objet:
 * Il lancera un thread autonome (pour pas bloquer le RA) qui se connectera au CA pour faire signer la demande de revocation.
 * Puis il se connectera au Repository pour envoyer la revocation.
 * Une methode permettra au RA de savoir a tout moment ou en est la progression de la revocation, et si elle à échoué ou pas.
 * 
 * Comment ça va marcher coté RA ?
 * Concretement lorsque le RA reçoit d'un client une demande de révocation il crée un objet RevocationRequest qu'il lance et met en attachment de la SelectionKey
 * A chaque fois qu'il va looper sur les Keys et tomber sur la SelectionKeys qui contient cet objet il va consulter son status. Tant que c'est en progression il le laisse faire.
 * Ensuite que le résultat soit positif ou négatif il renvoie la réponse récupérée, puis ferme la socket.
 *########################*/
}
