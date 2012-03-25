package Utils;

import java.nio.ByteBuffer;


public class StringSerializer implements ObjectSerializer<String> {
    
   int writtenTokenCount = 0 ;
   int readCharCount = 0;
   char[] data;
    
    public boolean serialize(ByteBuffer buffer, String s) {
    	/*
    	 * vrai si serialisation terminée, faux sinon
    	 */
    	
        char[] s_arr = s.toCharArray(); // on aurait pu utiliser charAt mais ça revient au même
        
        if(writtenTokenCount == 0) {
            if(buffer.remaining() < 4) { //4 taille d'un Integer
                return false;
            }
            else {
                buffer.putInt(s.length());
                writtenTokenCount = 1 ; //double emploi : savoir combien de charactères ont à écrit ET si l'on est deja en train de sérialiser
            }
        }
        int charAvailableSpace = buffer.remaining() / 2;
        int toWrite = Math.min(s.length() - writtenTokenCount +1, charAvailableSpace); //prend le minimum entre la taille du buffer et le nombre de charactères à écrire
        for (int i=0; i < toWrite; i++) {
        	buffer.putChar(s_arr[i+writtenTokenCount -1]); //écrit le char dans le buffer
        }
        if(s.length() - writtenTokenCount +1 <= charAvailableSpace) { //si l'espace restant dans le buffer est superieur au nombre de char a ecrire alors on a tout écrit
        	writtenTokenCount = 0;
        	return true;
        }
        else {
        	writtenTokenCount += toWrite; // incrémente writtenTokenCount sinon
        	return false;
        }
    }
    
    
    
    public String deserialize(ByteBuffer buffer) {
    	
        if(readCharCount == 0) {
        	
        	if(buffer.remaining() < 4)
        		return null;
        	int length = buffer.getInt();
        	if (length == 0) { //si on lit une taille nulle on retourne une String de taille 0
        		return "";
        	}
        	data = new char[length]; //on créer un tableau de char de la taille de la string a lire
        	readCharCount += 1;
        }
        
        int availableSpace = buffer.remaining() / 2;
        int toRead = Math.min(availableSpace,data.length - readCharCount +1); //comme pour serialize mais pour la lecture
        for(int i=0; i < toRead ; i++) {
        	data[i+readCharCount -1] = buffer.getChar(); // lit un char
        }
        if (availableSpace >= data.length - readCharCount +1) { 
        	readCharCount = 0;
        	char[] data2 = data; // on crée data2 pour pouvoir remettre data a null avant de retourner le String
        	data = null;
        	return String.valueOf(data2);
        }
        else {
        	readCharCount += toRead;
        	return null;
        }
    }
    
}