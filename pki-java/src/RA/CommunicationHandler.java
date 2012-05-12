package RA;

public interface CommunicationHandler {
	/* 
	 * Interface for all the class that will handle RAserver data
	 */
	public void setRead(byte[] bts);
	public byte[] getBytesToWrite();
	public void resetBytesToWrite();
	
}
