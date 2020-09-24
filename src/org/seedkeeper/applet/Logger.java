package org.seedkeeper.applet;

import javacard.framework.Util;
import javacard.framework.ISOException;



/**
 * Logger Class
 * <p>
 * 
 * Logs are simply stored in a array and rotated
 * 
 * 
 * Log fields:
 * 
 * <pre>
 *   byte instruction: the operation (APDU command) executed
 *   short id1: id of secret involved
 *   short id2: id of second (optional) secret 
 *   short result: whether operation was successful or exception code
 * </pre>
 * 
 * todo: method to add timestamp from specific APDU?
 * 
 */
public class Logger {
    
    public final static byte LOG_SIZE = (byte) (7);
    private final static byte LOG_INS = (byte) 0; 
    private final static byte LOG_ID1 = (byte) 1; 
    private final static byte LOG_ID2 = (byte) 3; 
    private final static byte LOG_RES = (byte) 5; 
    
    public final static short SW_LOGGER_ERROR = (short) 0x9C0A;
    
    /** The array storing the logs **/
    private byte[] logs;
    
    /** index to last log */
    private short head;
    
    /** number of logs **/
    private short nbtotal_logs;
    //private short nbavail_logs; // todo: remove?
    private short LOGS_SIZE;
    
    /** Iterator on logs. Stores the offset of the last retrieved log record **/
    private short it;
    
    /**
     * Constructor for the Logger class.
     * 
     * @param mem_size
     *            The size (in byte) of memory allocated
     */
    public Logger(short nb_records) {
        LOGS_SIZE= (short)(nb_records*LOG_SIZE);
        logs= new byte[LOGS_SIZE];
        head = (short)0;
        nbtotal_logs= (short)0;
        //nbavail_logs= (short)0;
        it=(short)0;
    }
    
    public void createLog(byte ins, short id1, short id2, short res){
        
        this.setLog(ins, id1, id2, res);
        
        // update head so it that always points to an available slot
        head= (short) ( ((short)(head+LOG_SIZE)) % (LOGS_SIZE) );
        // update nbtotal_logs
        if (nbtotal_logs<0x7FFF)
            nbtotal_logs++;
    }
    
    public void updateLog(byte ins, short id1, short id2, short res){
        
        // go back to last log
        short next= head;
        // head= (short) ( (head-LOG_SIZE)%(LOGS_SIZE) ); //TODO: check correctness?
        if (head>=LOG_SIZE)
            head= (short)(head-LOG_SIZE);
        else
            head= (short)(LOGS_SIZE-LOG_SIZE);
        
        // update log
        this.setLog(ins, id1, id2, res);
        
        // forward to next log
        head=next;
    }
    
    private void setLog(byte ins, short id1, short id2, short res){
        // fill slot currently indexed in head
        logs[(short)(head+LOG_INS)]= ins;
        Util.setShort(logs, (short)(head+LOG_ID1), id1);
        Util.setShort(logs, (short)(head+LOG_ID2), id2);
        Util.setShort(logs, (short)(head+LOG_RES), res);
    }
    
    //Deprecated - to remove?
//  public void addLog(byte ins, short id1, short id2, short res){
//      logs[(short)(head+LOG_INS)]= ins;
//      Util.setShort(logs, (short)(head+LOG_ID1), id1);
//      Util.setShort(logs, (short)(head+LOG_ID2), id2);
//      Util.setShort(logs, (short)(head+LOG_RES), res);
//      
//      // update head
//      short base= head;
//      head= (short) ( ((short)(head+LOG_SIZE)) % (LOGS_SIZE) );
//      // update nbtotal_logs
//      if (nbtotal_logs<0x7FFF)
//          nbtotal_logs++;
//      
//      //return base;
//  }
    // TODO: remove or refactor  
//    public short updateLogResult(short base, short res){
//        if ( (base%LOG_SIZE != 0) || (base>=LOGS_SIZE) || (base<0))
//            ISOException.throwIt(SW_LOGGER_ERROR); // should not happen!
//        
//        Util.setShort(logs, (short)(base+LOG_RES), res);
//        return base;
//    }
    
    /**
     * Resets the objects iterator and retrieves the information record of the
     * first object, if any.
     * <p>
     * 
     * @param buffer
     *            The byte array into which the record will be copied
     * @param offset
     *            The offset in buffer[] at which the record will be copied
     * @return True if an object was found. False if there are no objects.
     * 
     * @see #getNextRecord
     */
    public boolean getFirstRecord(byte[] buffer, short offset) {
      if (head>=LOG_SIZE)
          it = (short)(head-LOG_SIZE);
      else
          it = (short)(LOGS_SIZE-LOG_SIZE);
      
      Util.setShort(buffer, offset, nbtotal_logs);
      Util.setShort(buffer, (short)(offset+2), (short)(LOGS_SIZE/LOG_SIZE));
      //return true;
      return getNextRecord(buffer, (short)(offset+4));
    }
    
    /**
     * Retrieves the information record of the next object, if any.
     * <p>
     * 
     * @param buffer
     *            The byte array into which the record will be copied
     * @param offset
     *            The offset in buffer[] at which the record will be copied
     * @return True if an object was found. False if there are no more objects
     *         to inspect.
     * @see #getFirstRecord
     */
    public boolean getNextRecord(byte[] buffer, short offset) {
        if (it == head)
            return false;
        // Setting log ins
        buffer[(short)(offset + LOG_INS)]= logs[(short)(it+LOG_INS)];
        // Setting log id1
        Util.setShort( buffer, (short)(offset+LOG_ID1), Util.getShort(logs, (short)(it+LOG_ID1)) );
        // Setting log id2
        Util.setShort( buffer, (short)(offset+LOG_ID2), Util.getShort(logs, (short)(it+LOG_ID2)) );
        // Setting log res
        Util.setShort( buffer, (short)(offset+LOG_RES), Util.getShort(logs, (short)(it+LOG_RES)) );
        // update iterator todo: it= (it-LOG_SIZE)%LOGS_SIZE;
        if (it>=LOG_SIZE)
            it = (short)(it-LOG_SIZE);
        else
            it = (short)(LOGS_SIZE-LOG_SIZE);
        return true;
    }

}// end of Logger class
