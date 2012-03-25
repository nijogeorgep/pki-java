package Utils;

import java.nio.ByteBuffer;


public interface ObjectSerializer<T> {

    boolean serialize(ByteBuffer buffer, T t);
   
    T deserialize(ByteBuffer buf);
    
}
