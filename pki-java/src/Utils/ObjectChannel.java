/*
 * ObjectChannel.java
 *
 * Created on 30 novembre 2011, 09:14
 *
 * To change this template, choose Tools | Template Manager
 * and open the template in the editor.
 */

package Utils;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;

public class ObjectChannel<T> {
    
    private final ObjectSerializer<T> serializer;
    private ByteChannel channel;
    
    //-- paramètres pour write----
    private ByteBuffer  b_in = ByteBuffer.allocate(5);
    private boolean isSerialized = false;
    //----------------------------
    
    //-- paramètres pour read ----
    private ByteBuffer  b_out = ByteBuffer.allocate(5);
    private boolean reste_a_ecrire = false;
    private T objDeserialized = null;
    //----------------------------
    
    public ObjectChannel(ObjectSerializer<T> ser, ByteChannel c) {
        this.serializer = ser;
        this.channel = c;   
    }
    
    public boolean write(T Obj) throws IOException {
    	
        do {
            if(!reste_a_ecrire) {//il ne reste rien à écrire
                b_out.clear();
                isSerialized = this.serializer.serialize(this.b_out, Obj);//vrai serialisation terminée, faux pas fini
                b_out.flip(); //on flip pour quand même écrire ce qu'on a pu serialiser
                reste_a_ecrire=true;
            }
            
            while(this.b_out.hasRemaining()) {
                int written = this.channel.write(this.b_out); //on écrit ce que l'on peut dans le buffer
                
                if(written == -1) //probleme avec la socket
                    throw new IOException();
                else  if(written == 0) // uniquement pour le mode non bloquant on a rien lu (channel plein ||  buffer vide)
                    return false ;
            }
            reste_a_ecrire=false;
            
        }while(!isSerialized);
        b_out.clear();
        return true ;
    }
    
    public T read() throws IOException {
        
     do{   
    	int read = channel.read(b_in);
    	if(read == 0) //pour le non bloquant
    		return null;
    	else if(read == -1) //prob avec la socket
    		throw new EOFException();
    	b_in.flip(); // on flip pour que deserialize n'ait plus qu'a lire les datas
    	objDeserialized = this.serializer.deserialize(b_in); //on tente un déserialisation
    	b_in.compact(); // on compact car même si on a récupéré un objet read à deja pu commencer a lire un autre objet
     } while(objDeserialized == null);

     return objDeserialized; //on retourne l'objet

    }
}
