/*
 * SatoChip Bitcoin Hardware Wallet based on javacard
 * (c) 2015 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin  
 *               
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *   
 */    

package org.seedkeeper.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

// very limited Hmac-SHA512 implementation
public class HmacSha512 {

    public static final short BLOCKSIZE=128; // 128 bytes 
    public static final short HASHSIZE=64;
    private static byte[] data;
    private static MessageDigest sha512;
    
    public static void init(byte[] tmp, MessageDigest sha512_hash){
        data= tmp;
        sha512= sha512_hash;
    }
    

    /**
     * Compute the HMAC-SHA512 of given key and message.
     * Uses a temporary buffer for intermediate computations as set in init().
     * Result is written in the mac bytearray. 
     * The mac bytearray can be the same as the key or message bytearray.
     * 
     * @param key the buffer storing the HMAC key
     * @param key_offset offset for the key in buffer
     * @param key_length the length of the key in bytes, should not exceed 128 bytes
     * @param message the buffer storing the HMAC message
     * @param message_offset offset for the message in buffer
     * @param message_length the length of the message in bytes, should not exceed 64 bytes
     * @param mac the buffer where the final result is written
     * @param mac_offset offset for the computed mac in buffer
     * @return the length in bytes of the HMAC result (64 bytes)
     * 
     * **/
    public static short computeHmacSha512(byte[] key, short key_offset, short key_length, 
            byte[] message, short message_offset, short message_length,
            byte[] mac, short mac_offset){
        
        if (key_length>BLOCKSIZE || key_length<0){
            ISOException.throwIt(SeedKeeper.SW_HMAC_UNSUPPORTED_KEYSIZE); // don't accept keys bigger than block size 
        }
        if (message_length>HASHSIZE || message_length<0){
            ISOException.throwIt(SeedKeeper.SW_HMAC_UNSUPPORTED_MSGSIZE); // don't accept message bigger than block size (should be sufficient for BIP32)
        }
        
        // compute inner hash
        for (short i=0; i<key_length; i++){
            data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x36));
        }
        Util.arrayFillNonAtomic(data, key_length, (short)(BLOCKSIZE-key_length), (byte)0x36);       
        Util.arrayCopyNonAtomic(message, message_offset, data, BLOCKSIZE, message_length);
        sha512.reset();
        sha512.doFinal(data, (short)0, (short)(BLOCKSIZE+message_length), data, BLOCKSIZE); // copy hash result to data buffer!
        
        // compute outer hash
        for (short i=0; i<key_length; i++){
            data[i]= (byte) (key[(short)(key_offset+i)] ^ (0x5c));
        }
        Util.arrayFillNonAtomic(data, key_length, (short)(BLOCKSIZE-key_length), (byte)0x5c);
        // previous hash already copied to correct offset in data
        sha512.reset();
        sha512.doFinal(data, (short)0, (short)(BLOCKSIZE+HASHSIZE), mac, mac_offset);
        
        return HASHSIZE;
    }   
    
}
