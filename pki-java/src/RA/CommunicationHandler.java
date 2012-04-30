package RA;

public interface CommunicationHandler {
	
	public void setRead(byte[] bts);
	public byte[] getBytesToWrite();
	public void resetBytesToWrite();
	
	public Integer getDistinguishNumber();
}
