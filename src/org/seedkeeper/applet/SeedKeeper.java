/*
 * SatoChip SeedKeeper - Store your seeds on javacard
 * (c) 2020 by Toporin - 16DMCk4WUaHofchAhpMaQS4UPm4urcy2dN
 * Sources available on https://github.com/Toporin                   
 *                  
 *  
 * Based on the M.US.C.L.E framework:
 * see http://pcsclite.alioth.debian.org/musclecard.com/musclecard/
 * see https://github.com/martinpaljak/MuscleApplet/blob/d005f36209bdd7020bac0d783b228243126fd2f8/src/com/musclecard/CardEdge/CardEdge.java
 * 
 *  MUSCLE SmartCard Development
 *      Authors: Tommaso Cucinotta <cucinotta@sssup.it>
 *               David Corcoran    <corcoran@linuxnet.com>
 *      Description:      CardEdge implementation with JavaCard
 *      Protocol Authors: Tommaso Cucinotta <cucinotta@sssup.it>
 *                        David Corcoran <corcoran@linuxnet.com>
 *      
 * BEGIN LICENSE BLOCK
 * Copyright (C) 1999-2002 David Corcoran <corcoran@linuxnet.com>
 * Copyright (C) 2015-2019 Toporin 
 * All rights reserved.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END LICENSE_BLOCK  
 */

package org.seedkeeper.applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
//import javacard.security.KeyPair;
import javacard.security.Signature;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;


public class SeedKeeper extends javacard.framework.Applet { 

    /* constants declaration */

    /** 
     * VERSION HISTORY
     * PROTOCOL VERSION: changes that impact compatibility with the client side
     * APPLET VERSION:   changes with no impact on compatibility of the client
     */
    // 0.1-0.1: initial version
    // 0.2-0.1: WIP
    private final static byte PROTOCOL_MAJOR_VERSION = (byte) 0; 
    private final static byte PROTOCOL_MINOR_VERSION = (byte) 2;
    private final static byte APPLET_MAJOR_VERSION = (byte) 0;
    private final static byte APPLET_MINOR_VERSION = (byte) 1;   

    // Maximum number of PIN codes
    private final static byte MAX_NUM_PINS = (byte) 8; // TODO: set to 2?

    // Maximum size for the extended APDU buffer 
    private final static short EXT_APDU_BUFFER_SIZE = (short) 320;
    private final static short TMP_BUFFER_SIZE = (short) 256;
    private final static short TMP_BUFFER2_SIZE = (short) 32;
    
    // Minimum PIN size
    private final static byte PIN_MIN_SIZE = (byte) 4;
    // Maximum PIN size
    private final static byte PIN_MAX_SIZE = (byte) 16;// TODO: increase size?
    // PIN[0] initial value...
    private final static byte[] PIN_INIT_VALUE={(byte)'M',(byte)'u',(byte)'s',(byte)'c',(byte)'l',(byte)'e',(byte)'0',(byte)'0'};

    // code of CLA byte in the command APDU header
    private final static byte CardEdge_CLA = (byte) 0xB0;

    /****************************************
     * Instruction codes *
     ****************************************/

    // Applet initialization
    private final static byte INS_SETUP = (byte) 0x2A;

    // Keys' use and management
    // private final static byte INS_IMPORT_KEY = (byte) 0x32;
    // private final static byte INS_RESET_KEY = (byte) 0x33;
    // private final static byte INS_GET_PUBLIC_FROM_PRIVATE= (byte)0x35;

    // External authentication
    //private final static byte INS_CREATE_PIN = (byte) 0x40; // deprecated
    private final static byte INS_VERIFY_PIN = (byte) 0x42;
    private final static byte INS_CHANGE_PIN = (byte) 0x44;
    private final static byte INS_UNBLOCK_PIN = (byte) 0x46;
    private final static byte INS_LOGOUT_ALL = (byte) 0x60;

    // Status information
    //private final static byte INS_LIST_PINS = (byte) 0x48; // deprecated
    private final static byte INS_GET_STATUS = (byte) 0x3C;
    private final static byte INS_CARD_LABEL= (byte)0x3D;
    private final static byte INS_SET_NFC_POLICY = (byte) 0x3E;

    // HD wallet
    //private final static byte INS_BIP32_IMPORT_SEED= (byte) 0x6C;
    //private final static byte INS_BIP32_RESET_SEED= (byte) 0x77;
    private final static byte INS_BIP32_GET_AUTHENTIKEY= (byte) 0x73;
    //private final static byte INS_BIP32_SET_AUTHENTIKEY_PUBKEY= (byte)0x75;
    private final static byte INS_BIP32_GET_EXTENDED_KEY= (byte) 0x6D;
    // private final static byte INS_BIP32_SET_EXTENDED_PUBKEY= (byte) 0x74;
    // private final static byte INS_SIGN_MESSAGE= (byte) 0x6E;
    // private final static byte INS_SIGN_SHORT_MESSAGE= (byte) 0x72;
    // private final static byte INS_SIGN_TRANSACTION= (byte) 0x6F;
    // private final static byte INS_PARSE_TRANSACTION = (byte) 0x71;
    // private final static byte INS_CRYPT_TRANSACTION_2FA = (byte) 0x76;
    // private final static byte INS_SET_2FA_KEY = (byte) 0x79;    
    // private final static byte INS_RESET_2FA_KEY = (byte) 0x78;
    // private final static byte INS_SIGN_TRANSACTION_HASH= (byte) 0x7A;

    // secure channel
    private final static byte INS_INIT_SECURE_CHANNEL = (byte) 0x81;
    private final static byte INS_PROCESS_SECURE_CHANNEL = (byte) 0x82;

    // SeedKeeper
    private final static byte INS_GET_SEEDKEEPER_STATUS= (byte)0xA7;
    private final static byte INS_GENERATE_MASTERSEED= (byte)0xA0;
    private final static byte INS_GENERATE_RANDOM_SECRET= (byte)0xA3;
    private final static byte INS_GENERATE_2FA_SECRET= (byte)0xAE; 
    private final static byte INS_IMPORT_SECRET= (byte)0xA1;
    private final static byte INS_EXPORT_SECRET= (byte)0xA2;
    private final static byte INS_EXPORT_SECRET_TO_SATOCHIP= (byte)0xA8;
    private final static byte INS_RESET_SECRET= (byte)0xA5;
    private final static byte INS_LIST_SECRET_HEADERS= (byte)0xA6;
    private final static byte INS_PRINT_LOGS= (byte)0xA9;
    private final static byte INS_EXPORT_AUTHENTIKEY= (byte) 0xAD;
    private final static byte INS_DERIVE_MASTER_PASSWORD= (byte) 0xAA;
    
    
    // Personalization PKI support
    private final static byte INS_IMPORT_PKI_CERTIFICATE = (byte) 0x92;
    private final static byte INS_EXPORT_PKI_CERTIFICATE = (byte) 0x93;
    private final static byte INS_SIGN_PKI_CSR = (byte) 0x94;
    private final static byte INS_EXPORT_PKI_PUBKEY = (byte) 0x98;
    private final static byte INS_LOCK_PKI = (byte) 0x99;
    private final static byte INS_CHALLENGE_RESPONSE_PKI= (byte) 0x9A;
    //private final static byte INS_IMPORT_PKI_PUBKEY = (byte) 0x90;
    //private final static byte INS_IMPORT_PKI_PRIVKEY = (byte) 0x91;
    //private final static byte INS_VERIFY_PKI_KEYPAIR = (byte) 0x97;
    //private final static byte INS_SET_ALLOWED_CARD_AID = (byte) 0x95;
    //private final static byte INS_GET_ALLOWED_CARD_AID = (byte) 0x96;
    
    // reset to factory settings
    // reset automatically when PIN is blocked and remove PUK?
    private final static byte INS_RESET_TO_FACTORY = (byte) 0xFF;
    
    /****************************************
     *          Error codes                 *
     ****************************************/

    /** Entered PIN is not correct */
    private final static short SW_PIN_FAILED = (short)0x63C0;// includes number of tries remaining
    ///** DEPRECATED - Entered PIN is not correct */
    //private final static short SW_AUTH_FAILED = (short) 0x9C02;
    /** Required operation is not allowed in actual circumstances */
    private final static short SW_OPERATION_NOT_ALLOWED = (short) 0x9C03;
    /** Required setup is not not done */
    private final static short SW_SETUP_NOT_DONE = (short) 0x9C04;
    /** Required setup is already done */
    private final static short SW_SETUP_ALREADY_DONE = (short) 0x9C07;
    /** Required feature is not (yet) supported */
    final static short SW_UNSUPPORTED_FEATURE = (short) 0x9C05;
    /** Required operation was not authorized because of a lack of privileges */
    private final static short SW_UNAUTHORIZED = (short) 0x9C06;
    ///** Algorithm specified is not correct */
    //private final static short SW_INCORRECT_ALG = (short) 0x9C09;
    /** Logger error */
    //public final static short SW_LOGGER_ERROR = (short) 0x9C0A;

    /** There have been memory problems on the card */
    private final static short SW_NO_MEMORY_LEFT = ObjectManager.SW_NO_MEMORY_LEFT; // 0x9C01
    /** DEPRECATED - Required object is missing */
    private final static short SW_OBJECT_NOT_FOUND= (short) 0x9C08;

    /** Incorrect P1 parameter */
    private final static short SW_INCORRECT_P1 = (short) 0x9C10;
    /** Incorrect P2 parameter */
    private final static short SW_INCORRECT_P2 = (short) 0x9C11;
    /** No more data available */
    private final static short SW_SEQUENCE_END = (short) 0x9C12;
    /** Invalid input parameter to command */
    private final static short SW_INVALID_PARAMETER = (short) 0x9C0F;

    // /** Eckeys initialized */
    // private final static short SW_ECKEYS_INITIALIZED_KEY = (short) 0x9C1A;

    /** Verify operation detected an invalid signature */
    private final static short SW_SIGNATURE_INVALID = (short) 0x9C0B;
    /** Operation has been blocked for security reason */
    private final static short SW_IDENTITY_BLOCKED = (short) 0x9C0C;
    /** For debugging purposes */
    private final static short SW_INTERNAL_ERROR = (short) 0x9CFF;
    // /** Very low probability error */
    private final static short SW_BIP32_DERIVATION_ERROR = (short) 0x9C0E;
    // /** Incorrect initialization of method */
    private final static short SW_INCORRECT_INITIALIZATION = (short) 0x9C13;
    /** Bip32 seed is not initialized => this is actually the authentikey*/
    private final static short SW_BIP32_UNINITIALIZED_SEED = (short) 0x9C14;
    // /** Bip32 seed is already initialized (must be reset before change)*/
    // private final static short SW_BIP32_INITIALIZED_SEED = (short) 0x9C17;
    //** DEPRECATED - Bip32 authentikey pubkey is not initialized*/
    //private final static short SW_BIP32_UNINITIALIZED_AUTHENTIKEY_PUBKEY= (short) 0x9C16;
    // /** Incorrect transaction hash */
    // private final static short SW_INCORRECT_TXHASH = (short) 0x9C15;
    // /** 2FA already initialized*/
    // private final static short SW_2FA_INITIALIZED_KEY = (short) 0x9C18;
    // /** 2FA uninitialized*/
    // private final static short SW_2FA_UNINITIALIZED_KEY = (short) 0x9C19;
    
    /** Lock error**/
    private final static short SW_LOCK_ERROR= (short) 0x9C30;
    /** Export not allowed **/
    private final static short SW_EXPORT_NOT_ALLOWED= (short) 0x9C31;
    /** Usage not allowed **/
    private final static short SW_USAGE_NOT_ALLOWED= (short) 0x9C36;
    /** Secret data is too long for import **/
    private final static short SW_IMPORTED_DATA_TOO_LONG= (short) 0x9C32;
    /** Secret data is too short for import (allocated memory should fit secret perfectly)**/
    //private final static short SW_IMPORTED_DATA_TOO_SHORT= (short) 0x9C37;
    /** Wrong HMAC when importing Secret through Secure import**/
    private final static short SW_SECURE_IMPORT_WRONG_MAC= (short) 0x9C33;
    /** Wrong Fingerprint when importing Secret through Secure import**/
    private final static short SW_SECURE_IMPORT_WRONG_FINGERPRINT= (short) 0x9C34;
    /** wrong secret type for the requested operation **/
    private final static short SW_WRONG_SECRET_TYPE= (short) 0x9C35;

    /** HMAC errors */
    static final short SW_HMAC_UNSUPPORTED_KEYSIZE = (short) 0x9c1E;
    static final short SW_HMAC_UNSUPPORTED_MSGSIZE = (short) 0x9c1F;

    /** Secure channel */
    private final static short SW_SECURE_CHANNEL_REQUIRED = (short) 0x9C20;
    private final static short SW_SECURE_CHANNEL_UNINITIALIZED = (short) 0x9C21;
    private final static short SW_SECURE_CHANNEL_WRONG_IV= (short) 0x9C22;
    private final static short SW_SECURE_CHANNEL_WRONG_MAC= (short) 0x9C23;
    
    /** PKI error */
    private final static short SW_PKI_ALREADY_LOCKED = (short) 0x9C40;
    //private final static short SW_KEYPAIR_MISMATCH = (short) 0x9C41;

    /** NFC interface disabled **/
    static final short SW_NFC_DISABLED = (short) 0x9C48;
    static final short SW_NFC_BLOCKED = (short) 0x9C49;
    
    /** For instructions that have been deprecated*/
    private final static short SW_INS_DEPRECATED = (short) 0x9C26;
    /** CARD HAS BEEN RESET TO FACTORY */
    private final static short SW_RESET_TO_FACTORY = (short) 0xFF00;
    /** For debugging purposes 2 */
    private final static short SW_DEBUG_FLAG = (short) 0x9FFF;

    // KeyBlob Encoding in Key Blobs
    //private final static byte BLOB_ENC_PLAIN = (byte) 0x00;

    // Cipher Operations admitted in ComputeCrypt()
    private final static byte OP_INIT = (byte) 0x01;
    private final static byte OP_PROCESS = (byte) 0x02;
    private final static byte OP_FINALIZE = (byte) 0x03;

    // JC API 2.2.2 does not define these constants:
    private static final byte TYPE_AES_TRANSIENT_DESELECT = 14;
    private static final byte TYPE_AES_TRANSIENT_RESET = 13;
    private final static byte ALG_ECDSA_SHA_256= (byte) 33;
    private final static byte ALG_EC_SVDP_DH_PLAIN= (byte) 3; //https://javacard.kenai.com/javadocs/connected/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN
    private final static byte ALG_EC_SVDP_DH_PLAIN_XY= (byte) 6; //https://docs.oracle.com/javacard/3.0.5/api/javacard/security/KeyAgreement.html#ALG_EC_SVDP_DH_PLAIN_XY
    private final static short LENGTH_EC_FP_256= (short) 256;

    /****************************************
     * Instance variables declaration *
     ****************************************/

    // PIN and PUK objects, allocated during setup
    //private OwnerPIN[] pins, ublk_pins;
    private OwnerPIN pin, ublk_pin;
    
    //logger logs critical operations performed by the applet such as key export
    private Logger logger;
    private final static short LOGGER_NBRECORDS= (short) 100;
    
    private final static byte MAX_CARD_LABEL_SIZE = (byte) 64;
    private byte card_label_size= (byte)0x00;
    private byte[] card_label;
    
    // seeds data array
    // for each element: [id | mnemonic | passphrase | master_seed | encrypted_master_seed | label | status | settings ]
    // status: externaly/internaly generated, shamir, bip39 or electrum, 
    // settings: can be exported in clear, 
    //private final static short OM_SIZE= (short) 0xFFF; //todo: optimize memory for different cards?
    private static short OM_SIZE= (short) 0xFFF; // can be overwritten during applet installation using parameters
    private ObjectManager om_secrets;
    private AESKey om_encryptkey; // used to encrypt sensitive data in object
    private Cipher om_aes128_ecb; // 
    private short om_nextid;
    private final static short OM_TYPE= 0x00; // todo: refactor and remove (unused)
    
    // type of secrets stored
    private final static byte SECRET_TYPE_MASTER_SEED = (byte) 0x10;
    //private final static byte SECRET_TYPE_ENCRYPTED_MASTER_SEED = (byte) 0x20;// todo deprecate
    private final static byte SECRET_TYPE_BIP39_MNEMONIC = (byte) 0x30;
    //private final static byte SECRET_TYPE_BIP39_MNEMONIC_V2 = (byte) 0x31;
    private final static byte SECRET_TYPE_ELECTRUM_MNEMONIC = (byte) 0x40;
    private final static byte SECRET_TYPE_SHAMIR_SECRET_SHARE = (byte) 0x50;
    private final static byte SECRET_TYPE_PRIVKEY = (byte) 0x60;
    private final static byte SECRET_TYPE_PUBKEY = (byte) 0x70;
    private final static byte SECRET_TYPE_PUBKEY_AUTHENTICATED = (byte) 0x71; //RFU authentikey signed with known PKI subca.
    private final static byte SECRET_TYPE_KEY= (byte) 0x80;
    private final static byte SECRET_TYPE_PASSWORD= (byte) 0x90;
    private final static byte SECRET_TYPE_MASTER_PASSWORD= (byte) 0x91; // can be derived to generate many passwords
    private final static byte SECRET_TYPE_CERTIFICATE= (byte) 0xA0;
    private final static byte SECRET_TYPE_2FA= (byte) 0xB0; // to deprecate and use SECRET_TYPE_KEY instead
    private final static byte SECRET_TYPE_DATA= (byte) 0xC0;
    //private final static byte SECRET_TYPE_BITCOIN_DESCRIPTOR; // use data subtype
    
    // subtype (optionnal, default = 0)
    private final static byte SECRET_SUBTYPE_DEFAULT = (byte) 0x00;
    // for Masterseed 
    //private final static byte SECRET_SUBTYPE_BIP39 = (byte) 0x01;
    // for SECRET_TYPE_KEY
    private final static byte SECRET_SUBTYPE_ENTROPY = (byte) 0x10;

    // export policy 
    private final static byte SECRET_EXPORT_MASK = (byte) 0x03; // mask for the export controls
    private final static byte SECRET_EXPORT_FORBIDDEN = (byte) 0x00; // never allowed
    private final static byte SECRET_EXPORT_ALLOWED = (byte) 0x01; //plain or encrypted
    private final static byte SECRET_EXPORT_SECUREONLY = (byte) 0x02; // only encrypted with authentikey
    private final static byte SECRET_EXPORT_AUTHENTICATED = (byte) 0x03; // RFU: only encrypted with certified authentikey

    // use controls: use a secret to perform specific operations
    // For example a masterseed can be derived using BIP32, with extended keys exported
    // private final static byte SECRET_USAGE_MASK = (byte) 0x30; // mask for the export controls
    // private final static byte SECRET_USAGE_FORBIDDEN = (byte) 0x00; // never allowed
    // private final static byte SECRET_USAGE_ALLOWED = (byte) 0x10; // always allowed
    // private final static byte SECRET_USAGE_SECUREONLY = (byte) 0x20; // allowed only using encrypted export
    // private final static byte SECRET_USAGE_AUTHENTICATED = (byte) 0x30; // RFU: only encrypted with certified authentikey

    // origin
    private final static byte SECRET_ORIGIN_IMPORT_PLAIN= (byte) 0x01; 
    private final static byte SECRET_ORIGIN_IMPORT_SECURE = (byte) 0x02; 
    private final static byte SECRET_ORIGIN_ONCARD = (byte) 0x03; 
    
    // Offset
    private final static byte SECRET_OFFSET_TYPE=(byte) 0;
    private final static byte SECRET_OFFSET_ORIGIN=(byte) 1;
    private final static byte SECRET_OFFSET_EXPORT_CONTROL=(byte) 2;
    private final static byte SECRET_OFFSET_EXPORT_NBPLAIN=(byte) 3;
    private final static byte SECRET_OFFSET_EXPORT_NBSECURE=(byte) 4;
    private final static byte SECRET_OFFSET_EXPORT_COUNTER=(byte) 5; //(pubkey only) nb of time this pubkey has been used to export secret
    private final static byte SECRET_OFFSET_FINGERPRINT=(byte) 6; 
    //private final static byte SECRET_OFFSET_RFU1=(byte) 10; // deprecated, now used for secret subtype
    private final static byte SECRET_OFFSET_SUBTYPE=(byte) 10; // can be used to provide subtype context about the key 
    private final static byte SECRET_OFFSET_RFU2=(byte) 11; 
    private final static byte SECRET_OFFSET_LABEL_SIZE=(byte) 12;
    private final static byte SECRET_OFFSET_LABEL=(byte) 13;
    private final static byte SECRET_HEADER_SIZE=(byte) 13;
    private final static byte SECRET_FINGERPRINT_SIZE=(byte) 4;
        
    // label
    private final static byte MAX_LABEL_SIZE= (byte) 127; 
    private final static byte MAX_SEED_SIZE= (byte) 64; 
    private final static byte MIN_SEED_SIZE= (byte) 16;
    private static final byte[] ENTROPY_LABEL = {'e','n','t','r','o','p','y'};

    // secret size
    private final static byte MAX_RANDOM_SIZE= (byte) 64; 
    private final static byte MIN_RANDOM_SIZE= (byte) 16; 
    
    private final static byte AES_BLOCKSIZE= (byte)16;
    private final static byte SIZE_2FA= (byte)20;

    private final static short CHUNK_SIZE= (short)128; // MUST be a multiple of 16; cut secret in chunks for exportSecret()

    // secure channel for secure secret import/export: the secret is encrypted and maced with a symmetric key derived using ECDH
    private static final byte[] SECRET_CST_SC = {'s','e','c','k','e','y', 's','e','c','m','a','c'};
    private byte[] secret_sc_buffer;
    private AESKey secret_sc_sessionkey;
    private Cipher secret_sc_aes128_cbc;
    private MessageDigest secret_sha256;
    
    // Secret format for various secret types
    // common data_header: [ type(1b) | origin(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | export_pubkey_counter(1b) | fingerprint (4b) | RFU(2b) | label_size(1b) | label ]
    // SECRET_TYPE_MASTER_SEED: [ size(1b) | seed_blob ]
    // SECRET_TYPE_MASTER_SEED (subtype SECRET_SUBTYPE_BIP39): [ masterseed_size(1b) | masterseed | wordlist_selector(1b) | entropy_size(1b) | entropy(<=32b) | passphrase_size(1b) | passphrase] where entropy is 16-32 bytes as defined in BIP39 (this format is backward compatible with SECRET_TYPE_MASTER_SEED)
    // SECRET_TYPE_ENCRYPTED_MASTER_SEED: [ size(1b) | seed_blob | passphrase_size(1b) | passphrase | e(1b) ] //RFU
    // SECRET_TYPE_BIP39_MNEMONIC: [mnemonic_size(1b) | mnemonic | passphrase_size(1b) | passphrase ]
    // SECRET_TYPE_ELECTRUM_MNEMONIC: [mnemonic_size(1b) | mnemonic | passphrase_size(1b) | passphrase ]
    // SECRET_TYPE_SHAMIR_SECRET_SHARE: [TODO]
    // SECRET_TYPE_PRIVKEY: [keysize(1b) | key ]
    // SECRET_TYPE_PUBKEY: [keysize(1b) | key ]
    // SECRET_TYPE_KEY: [keysize(1b) | key]
    // SECRET_TYPE_PASSWORD: [password_size(1b) | password]
    // SECRET_TYPE_PASSWORD (subtype 0x01): [password_size(1b) | password | login_size(1b) | login | url_size(1b) | url]
    // SECRET_TYPE_MASTER_PASSWORD: [password_size(1b) | password]
    // SECRET_TYPE_BITCOIN_DESCRIPTOR: [format(1b) | size(2b) | descriptor] // format: RFU
    // SECRET_TYPE_DATA: [format(1b) | size(2b) | data]

    // Buffer for storing extended APDUs
    private byte[] recvBuffer; 
    private byte[] tmpBuffer; //used for hmac computation
    private byte[] tmpBuffer2; //used in securechannel

    /* For the setup function - should only be called once */
    private boolean setupDone = false;

    // lock mechanism for multiple call to 
    private boolean lock_enabled = false;
    private byte lock_ins=(byte)0;
    private byte lock_lastop=(byte)0;
    private byte lock_transport_mode= (byte)0;
    private short lock_id=-1;
    private short lock_id_pubkey=-1;
    //private short lock_recv_offset=(short)0;
    private short lock_data_size=(short)0;
    private short lock_data_remaining=(short)0;
    private short lock_obj_offset=(short)0;
    private short lock_obj_size=(short)0;
    
    
    // shared cryptographic objects
    private RandomData randomData;
    private KeyAgreement keyAgreement;
    private Signature sigECDSA;
    //private Cipher aes128;
    private MessageDigest sha256;
    private MessageDigest sha512;

    // reset to factory // TODO DEPRECATE
    // private byte[] reset_array;
    // private final static byte MAX_RESET_COUNTER= (byte)5;
    // private byte reset_counter=MAX_RESET_COUNTER;
    
    /*********************************************
     *  BIP32 Hierarchical Deterministic Wallet  *
     *********************************************/
    
    // seed derivation
    private static final byte[] BITCOIN_SEED = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    private static final byte BIP32_MAX_DEPTH = 10; // max depth in extended key from master (m/i is depth 1)
    private static final short BIP32_KEY_SIZE= 32; // size of extended key and chain code is 256 bits
    
    // offset in working buffer
    // recvBuffer=[ parent_chain_code (32b) | 0x00 | parent_key (32b) | buffer(index)(32b) | current_extended_key(32b) | current_chain_code(32b) | pubkey(65b) | path(40b)]
    private static final short BIP32_OFFSET_PARENT_CHAINCODE=0;
    private static final short BIP32_OFFSET_PARENT_SEPARATOR=BIP32_KEY_SIZE;
    private static final short BIP32_OFFSET_PARENT_KEY=BIP32_KEY_SIZE+1;
    private static final short BIP32_OFFSET_INDEX= (short)(2*BIP32_KEY_SIZE+1);
    private static final short BIP32_OFFSET_CHILD_KEY= (short)(BIP32_OFFSET_INDEX+BIP32_KEY_SIZE); 
    private static final short BIP32_OFFSET_CHILD_CHAINCODE= (short)(BIP32_OFFSET_CHILD_KEY+BIP32_KEY_SIZE);
    private static final short BIP32_OFFSET_PUB= (short)(BIP32_OFFSET_CHILD_CHAINCODE+BIP32_KEY_SIZE);
    private static final short BIP32_OFFSET_PUBX= (short)(BIP32_OFFSET_PUB+1);
    private static final short BIP32_OFFSET_PUBY= (short)(BIP32_OFFSET_PUBX+BIP32_KEY_SIZE);
    private static final short BIP32_OFFSET_END= (short)(BIP32_OFFSET_PUBY+BIP32_KEY_SIZE);
    
    //   bip32 keys
    private ECPrivateKey bip32_extendedkey; // object storing last extended key used

    // bip85 
    private static final byte[] BIP85_SALT = {'b','i','p','-','e','n','t','r','o','p','y','-','f','r','o','m','-','k'};
    

    /*********************************************
     *        Other data instances               *
     *********************************************/

    // secure channel
    private static final byte[] CST_SC = {'s','c','_','k','e','y', 's','c','_','m','a','c'};
    private boolean needs_secure_channel= true;
    private boolean initialized_secure_channel= false;
    private ECPrivateKey sc_ephemeralkey; 
    private AESKey sc_sessionkey;
    private Cipher sc_aes128_cbc;
    private byte[] sc_buffer;
    private static final byte OFFSET_SC_IV=0;
    private static final byte OFFSET_SC_IV_RANDOM=OFFSET_SC_IV;
    private static final byte OFFSET_SC_IV_COUNTER=12;
    private static final byte OFFSET_SC_MACKEY=16;
    private static final byte SIZE_SC_MACKEY=20;
    private static final byte SIZE_SC_IV= 16;
    private static final byte SIZE_SC_IV_RANDOM=12;
    private static final byte SIZE_SC_IV_COUNTER=SIZE_SC_IV-SIZE_SC_IV_RANDOM;
    private static final byte SIZE_SC_BUFFER=SIZE_SC_MACKEY+SIZE_SC_IV; // 36

    //private ECPrivateKey bip32_authentikey; // key used to authenticate data
    
    // additional options
    private short option_flags;

    // NFC 
    private static final byte NFC_ENABLED=0;
    private static final byte NFC_DISABLED=1; // can be re-enabled at any time
    private static final byte NFC_BLOCKED=2; // warning: cannot be re-enabled except with reset factory!
    private byte nfc_policy;

    /*********************************************
     *               PKI objects                 *
     *********************************************/
    private static final byte[] PKI_CHALLENGE_MSG = {'C','h','a','l','l','e','n','g','e',':'};
    private boolean personalizationDone=false;
    private ECPrivateKey authentikey_private;
    private ECPublicKey authentikey_public;
    private short authentikey_certificate_size=0;
    private byte[] authentikey_certificate;
    
    /****************************************
     * Methods *
     ****************************************/

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // extract install parameters if any
        byte aidLength = bArray[bOffset];
        short controlLength = (short)(bArray[(short)(bOffset+1+aidLength)]&(short)0x00FF);
        short dataLength = (short)(bArray[(short)(bOffset+1+aidLength+1+controlLength)]&(short)0x00FF);

        new SeedKeeper(bArray, (short) (bOffset+1+aidLength+1+controlLength+1), dataLength);
    }

    private SeedKeeper(byte[] bArray, short bOffset, short bLength) {

        // recover OM_SIZE from install params
        // For example, using Global Platform Pro:
        // .\gp.exe -f -install .\SeedKeeper.cap -params 0FFF
        if (bLength>=2){
            OM_SIZE= Util.getShort(bArray, bOffset);
        }

        pin = null;

        // NFC is enabled by default, can be modified with INS_SET_NFC_POLICY
        nfc_policy = NFC_ENABLED; 
        
        // Temporary working arrays
        try {
            tmpBuffer = JCSystem.makeTransientByteArray(TMP_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            tmpBuffer = new byte[TMP_BUFFER_SIZE];
        }
        try {
            tmpBuffer2 = JCSystem.makeTransientByteArray(TMP_BUFFER2_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            tmpBuffer2 = new byte[TMP_BUFFER2_SIZE];
        }
        // Initialize the extended APDU buffer
        try {
            // Try to allocate the extended APDU buffer on RAM memory
            recvBuffer = JCSystem.makeTransientByteArray(EXT_APDU_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            // Allocate the extended APDU buffer on EEPROM memory
            // This is the fallback method, but its usage is really not
            // recommended as after ~ 100000 writes it will kill the EEPROM cells...
            recvBuffer = new byte[EXT_APDU_BUFFER_SIZE];
        }

        // shared cryptographic objects
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        secret_sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha256= MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);    
        sigECDSA= Signature.getInstance(ALG_ECDSA_SHA_256, false); 
        HmacSha160.init(tmpBuffer);
        HmacSha512.init(tmpBuffer, sha512);
        try {
            keyAgreement = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false); 
        } catch (CryptoException e) {
            // TODO: remove if possible
            ISOException.throwIt(SW_UNSUPPORTED_FEATURE);// unsupported feature => use a more recent card!
        }

        //secure channel objects
        try {
            sc_buffer = JCSystem.makeTransientByteArray((short) SIZE_SC_BUFFER, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            sc_buffer = new byte[SIZE_SC_BUFFER];
        }
        try {
            // Put the AES key in RAM if we can.
            sc_sessionkey = (AESKey)KeyBuilder.buildKey(TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        } catch (CryptoException e) {
            try {
                // This uses a bit more RAM, but at least it isn't using flash.
                sc_sessionkey = (AESKey)KeyBuilder.buildKey(TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
            } catch (CryptoException x) {
                // Last option as it will wear out the flash eventually
                sc_sessionkey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            }
        }
        //sc_sessionkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false); // todo: make transient?
        sc_ephemeralkey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        sc_aes128_cbc= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); 
        
        //secret secure channel objects are used to create a secure channel for encrypting secrets for export to another device. 
        //They use a similar protocol as the secure channel used to secure apdu exchanges with the host.
        try {
            secret_sc_buffer = JCSystem.makeTransientByteArray((short) SIZE_SC_BUFFER, JCSystem.CLEAR_ON_DESELECT);
        } catch (SystemException e) {
            secret_sc_buffer = new byte[SIZE_SC_BUFFER];
        }
        try {
            // Put the AES key in RAM if we can.
            secret_sc_sessionkey = (AESKey)KeyBuilder.buildKey(TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
        } catch (CryptoException e) {
            try {
                // This uses a bit more RAM, but at least it isn't using flash.
                secret_sc_sessionkey = (AESKey)KeyBuilder.buildKey(TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
            } catch (CryptoException x) {
                // Last option as it will wear out the flash eventually
                secret_sc_sessionkey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
            }
        }
        //secret_sc_sessionkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        secret_sc_aes128_cbc= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false); 
        
        // Secret objects manager
        om_secrets= new ObjectManager(OM_SIZE);
        randomData.generateData(recvBuffer, (short)0, (short)AES_BLOCKSIZE);
        om_encryptkey= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        om_encryptkey.setKey(recvBuffer, (short)0); // data must be exactly 16 bytes long
        om_aes128_ecb= Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
       
        // logger
        logger= new Logger(LOGGER_NBRECORDS); 
        
        // BIP32
        bip32_extendedkey= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);

        // card label
        card_label= new byte[MAX_CARD_LABEL_SIZE];
        
        // perso PKI: generate public/private keypair
        authentikey_private= (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(authentikey_private);
        authentikey_public= (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, LENGTH_EC_FP_256, false); 
        Secp256k1.setCommonCurveParameters(authentikey_public);
        randomData.generateData(recvBuffer, (short)0, BIP32_KEY_SIZE);
        authentikey_private.setS(recvBuffer, (short)0, BIP32_KEY_SIZE); //random value first
        keyAgreement.init(authentikey_private);   
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form => silently fail after cap loaded
        authentikey_public.setW(recvBuffer, (short)0, (short)65);
        
        // finally, register applet
        register();
    } // end of constructor

    public boolean select() {
        /*
         * Application has been selected: Do session cleanup operation
         */
        LogOutAll();

        //todo: clear secure channel values?
        initialized_secure_channel=false;

        // check nfc policy
        if (nfc_policy == NFC_DISABLED || nfc_policy == NFC_BLOCKED){
            // check that the contact interface is used
            byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
            if (protocol != APDU.PROTOCOL_MEDIA_USB && protocol != APDU.PROTOCOL_MEDIA_DEFAULT) {
                ISOException.throwIt(SW_NFC_DISABLED);
            }
        }

        return true;
    }

    public void deselect() {
        LogOutAll();
    }

    public void process(APDU apdu) {
        // APDU object carries a byte array (buffer) to
        // transfer incoming and outgoing APDU header
        // and data bytes between card and CAD

        // At this point, only the first header bytes
        // [CLA, INS, P1, P2, P3] are available in
        // the APDU buffer.
        // The interface javacard.framework.ISO7816
        // declares constants to denote the offset of
        // these bytes in the APDU buffer

        if (selectingApplet())
            ISOException.throwIt(ISO7816.SW_NO_ERROR);

        byte[] buffer = apdu.getBuffer();
        // check SELECT APDU command
        if ((buffer[ISO7816.OFFSET_CLA] == 0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0xA4))
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND); // spurious select (see https://github.com/Toporin/SatochipApplet/issues/11)

        // verify the rest of commands have the
        // correct CLA byte, which specifies the
        // command structure
        if (buffer[ISO7816.OFFSET_CLA] != CardEdge_CLA)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        byte ins = buffer[ISO7816.OFFSET_INS];
        
        // TODO DEPRECATE
        // Reset to factory 
        //    To trigger reset to factory, user must insert and remove card a fixed number of time, 
        //    without sending any other command than 1 reset in between
        // if (ins == INS_RESET_TO_FACTORY){
        //     if (reset_array[0]==0){
        //         reset_counter--;
        //         reset_array[0]=(byte)1;
        //     }else{
        //         // if INS_RESET_TO_FACTORY is sent after any instruction, the reset process is aborted.
        //         reset_counter=MAX_RESET_COUNTER;
        //         ISOException.throwIt((short)(SW_RESET_TO_FACTORY + 0xFF));
        //     }
        //     if (reset_counter== 0) {
        //         reset_counter=MAX_RESET_COUNTER;
        //         resetToFactory();
        //         ISOException.throwIt(SW_RESET_TO_FACTORY);
        //     }
        //     ISOException.throwIt((short)(SW_RESET_TO_FACTORY + reset_counter));
        // }
        // else{
        //     reset_counter=MAX_RESET_COUNTER;
        //     reset_array[0]=(byte)1;
        // }
        
        // prepare APDU buffer
        if (ins != INS_GET_STATUS){
            short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
            if (bytesLeft != apdu.setIncomingAndReceive())
                ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // only 3 commands are allowed, the others must be wrapped in a secure channel command
        // the 3 commands are: get_status, initialize_secure_channel & process_secure_channel
        short sizeout=(short)0;
        if (ins == INS_GET_STATUS){
            sizeout= GetStatus(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }
        else if (ins == INS_INIT_SECURE_CHANNEL){
            sizeout= InitiateSecureChannel(apdu, buffer);
            apdu.setOutgoingAndSend((short) 0, sizeout);
            return;
        }
        else if (ins == INS_PROCESS_SECURE_CHANNEL){
            sizeout= ProcessSecureChannel(apdu, buffer);
            //todo: check if sizeout and buffer[ISO7816.OFFSET_LC] matches...
            //if sizeout>4, buffer[ISO7816.OFFSET_LC] should be equal to (sizeout-5)
            //todo: remove padding ? (it is actually not used)          
        }
        else if (needs_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_REQUIRED);
        }

        // at this point, the encrypted content has been deciphered in the buffer
        ins = buffer[ISO7816.OFFSET_INS];
        if (!setupDone && (ins != INS_SETUP)){
            if (personalizationDone ||
                    ((ins != INS_VERIFY_PIN) 
                    && (ins != INS_EXPORT_PKI_PUBKEY)
                    && (ins != INS_IMPORT_PKI_CERTIFICATE)
                    && (ins != INS_SIGN_PKI_CSR)
                    && (ins != INS_LOCK_PKI)) ){
                ISOException.throwIt(SW_SETUP_NOT_DONE);
            } 
        }
        if (setupDone && (ins == INS_SETUP))
            ISOException.throwIt(SW_SETUP_ALREADY_DONE);

        // check lock: for some operations, the same command instruction must be called several times successively
        // We must ensure that it is indeed the case
        if ((lock_enabled) && lock_ins!= ins){
            //resetLockException();
            resetLockThenThrow(SW_LOCK_ERROR, false);
        }

        switch (ins) {
            case INS_SETUP:
                sizeout= setup(apdu, buffer);
                break;
            case INS_VERIFY_PIN:
                sizeout= VerifyPIN(apdu, buffer);
                break;
            // case INS_CREATE_PIN: // DEPRECATED
            //     sizeout= CreatePIN(apdu, buffer);
            //     break;
            case INS_CHANGE_PIN:
                sizeout= ChangePIN(apdu, buffer);
                break;
            case INS_UNBLOCK_PIN:
                sizeout= UnblockPIN(apdu, buffer);
                break;
            case INS_LOGOUT_ALL:
                sizeout= LogOutAll();
                break;
            // case INS_LIST_PINS: // DEPRECATED
            //     sizeout= ListPINs(apdu, buffer);
            //     break;
            case INS_GET_STATUS:
                sizeout= GetStatus(apdu, buffer);
                break;
            case INS_GET_SEEDKEEPER_STATUS:
                sizeout= GetSeedKeeperStatus(apdu, buffer);
                break;
            case INS_CARD_LABEL:
                sizeout= card_label(apdu, buffer);
                break;
            case INS_SET_NFC_POLICY:
                sizeout= setNfcPolicy(apdu, buffer);
                break;
            case INS_BIP32_GET_AUTHENTIKEY:
                sizeout= getBIP32AuthentiKey(apdu, buffer);
                break;
            case INS_GENERATE_MASTERSEED:
                sizeout= generateMasterseed(apdu, buffer);
                break;
            case INS_GENERATE_2FA_SECRET:
                sizeout= generate2FASecret(apdu, buffer);
                break;
            case INS_GENERATE_RANDOM_SECRET:
                sizeout = generateRandomSecret(apdu, buffer);
                break;
            case INS_DERIVE_MASTER_PASSWORD:
                sizeout= deriveMasterPassword(apdu, buffer);
                break;
            case INS_BIP32_GET_EXTENDED_KEY:
                sizeout= getBIP32ExtendedKey(apdu, buffer);
                break;
            case INS_IMPORT_SECRET:
                sizeout= importSecret(apdu, buffer);
                break;
            case INS_EXPORT_SECRET:
                sizeout= exportSecret(apdu, buffer);
                break;
            case INS_EXPORT_SECRET_TO_SATOCHIP:
                sizeout= exportSecretToSatochip(apdu, buffer);
                break;
            case INS_RESET_SECRET:
                sizeout= resetSecret(apdu, buffer);
                break;
            case INS_LIST_SECRET_HEADERS:
                sizeout= listSecretHeaders(apdu, buffer);
                break;
            case INS_PRINT_LOGS:
                sizeout= printLogs(apdu, buffer);
                break;
            case INS_EXPORT_AUTHENTIKEY:
                sizeout= getAuthentikey(apdu, buffer);
                break;    
            //PKI
            case INS_EXPORT_PKI_PUBKEY:
                sizeout= export_PKI_pubkey(apdu, buffer);
                break;
            case INS_IMPORT_PKI_CERTIFICATE:
                sizeout= import_PKI_certificate(apdu, buffer);
                break;
            case INS_EXPORT_PKI_CERTIFICATE:
                sizeout= export_PKI_certificate(apdu, buffer);
                break;
            case INS_SIGN_PKI_CSR:
                sizeout= sign_PKI_CSR(apdu, buffer);
                break;
            case INS_LOCK_PKI:
                sizeout= lock_PKI(apdu, buffer);
                break;
            case INS_CHALLENGE_RESPONSE_PKI:
                sizeout= challenge_response_pki(apdu, buffer);
                break;
            // default
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }//end of switch

        // Prepare buffer for return
        if (sizeout==0){
            return;
        }
        else if ((ins == INS_GET_STATUS) || (ins == INS_INIT_SECURE_CHANNEL)) {
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        else if (needs_secure_channel) { // encrypt response
            // buffer contains the data (sizeout)
            // for encryption, data is padded with PKCS#7
            //short blocksize=(short)16;
            short padsize= (short) (AES_BLOCKSIZE - sizeout%AES_BLOCKSIZE);

            Util.arrayCopy(buffer, (short)0, tmpBuffer, (short)0, sizeout);
            Util.arrayFillNonAtomic(tmpBuffer, sizeout, padsize, (byte)padsize);//padding
            Util.arrayCopy(sc_buffer, OFFSET_SC_IV, buffer, (short)0, SIZE_SC_IV);
            sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_ENCRYPT, sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
            short sizeoutCrypt=sc_aes128_cbc.doFinal(tmpBuffer, (short)0, (short)(sizeout+padsize), buffer, (short) (SIZE_SC_IV+2));
            Util.setShort(buffer, (short)SIZE_SC_IV, sizeoutCrypt);
            sizeout= (short)(SIZE_SC_IV+2+sizeoutCrypt);
            //send back
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }
        else {
            apdu.setOutgoingAndSend((short) 0, sizeout);
        }

    } // end of process method

    /** 
     * Setup APDU - initialize the applet and reserve memory
     * This is done only once during the lifetime of the applet
     * 
     * ins: INS_SETUP (0x2A) 
     * p1: 0x00
     * p2: 0x00
     * data: [default_pin_length(1b) | default_pin | 
     *        pin_tries0(1b) | ublk_tries0(1b) | pin0_length(1b) | pin0 | ublk0_length(1b) | ublk0 | 
     *        pin_tries1(1b) | ublk_tries1(1b) | pin1_length(1b) | pin1 | ublk1_length(1b) | ublk1 | 
     *        RFU(2b) | RFU(2b) | RFU(3b) |
     *        option_flags(2b - RFU) | 
     *        ]
     * where: 
     *      default_pin: {0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30};
     *      pin_tries: max number of PIN try allowed before the corresponding PIN is blocked
     *      ublk_tries:  max number of UBLK(unblock) try allowed before the PUK is blocked
     *      option_flags: flags to define up to 16 additional options       
     * return: none
     */
    private short setup(APDU apdu, byte[] buffer) {
        personalizationDone=true;// perso PKI should not be modifiable once setup is done
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short base = (short) (ISO7816.OFFSET_CDATA);
        byte numBytes = buffer[base++];
        bytesLeft--;

        // Default PIN, ignore

        //OwnerPIN pin = pins[0];

        // if (!CheckPINPolicy(buffer, base, numBytes))
        //     ISOException.throwIt(SW_INVALID_PARAMETER);

        // byte triesRemaining = pin.getTriesRemaining();
        // if (triesRemaining == (byte) 0x00)
        //     ISOException.throwIt(SW_IDENTITY_BLOCKED);
        // if (!pin.check(buffer, base, numBytes))
        //     ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));

        base += numBytes;
        bytesLeft-=numBytes;

        byte pin_tries = buffer[base++];
        byte ublk_tries = buffer[base++];
        numBytes = buffer[base++];
        bytesLeft-=3;

        // PIN0
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER); 

        if (pin == null)
            pin = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
        pin.update(buffer, base, numBytes);

//        pins[0] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);//TODO: new pin or update pin?
//        pins[0].update(buffer, base, numBytes);

        base += numBytes;
        bytesLeft-=numBytes;
        numBytes = buffer[base++];
        bytesLeft--;

        // PUK0
        if (!CheckPINPolicy(buffer, base, numBytes))
            ISOException.throwIt(SW_INVALID_PARAMETER);

        if (ublk_pin == null)
            ublk_pin = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
        ublk_pin.update(buffer, base, numBytes);

        base += numBytes;
        bytesLeft-=numBytes;

        pin_tries = buffer[base++];
        ublk_tries = buffer[base++];
        numBytes = buffer[base++];
        bytesLeft-=3;

        // PIN1 is deprecated, ignore

        // if (!CheckPINPolicy(buffer, base, numBytes))
        //     ISOException.throwIt(SW_INVALID_PARAMETER);

        // if (pins[1]==null)
        //     pins[1] = new OwnerPIN(pin_tries, PIN_MAX_SIZE);
        // pins[1].update(buffer, base, numBytes);

        base += numBytes;
        bytesLeft-=numBytes;
        numBytes = buffer[base++];
        bytesLeft--;

        // PUK1 is deprecated, ignore

        // if (!CheckPINPolicy(buffer, base, numBytes))
        //     ISOException.throwIt(SW_INVALID_PARAMETER);

        // if (ublk_pins[1]==null)
        //     ublk_pins[1] = new OwnerPIN(ublk_tries, PIN_MAX_SIZE);
        // ublk_pins[1].update(buffer, base, numBytes);
        
        base += numBytes;
        bytesLeft-=numBytes;

        short RFU= Util.getShort(buffer, base); // secmem_size deprecated => RFU
        base += (short) 2;
        RFU = Util.getShort(buffer, base); //mem_size deprecated => RFU
        base += (short) 2;
        bytesLeft-=4;

        RFU = buffer[base++]; //create_object_ACL deprecated => RFU
        RFU = buffer[base++]; //create_key_ACL deprecated => RFU
        RFU = buffer[base++]; //create_pin_ACL deprecated => RFU
        bytesLeft-=3;
        
        // parse options
        option_flags=0;
        if (bytesLeft>=2){
            option_flags = Util.getShort(buffer, base);
            base+=(short)2;
            bytesLeft-=(short)2;
        }
        
        // bip32
        Secp256k1.setCommonCurveParameters(bip32_extendedkey);

        om_nextid= (short)0;
        setupDone = true;
        return (short)0;//nothing to return
    }

    /****************************************
     *           Utility functions          *
     ****************************************/
    

    /** Checks if PIN policies are satisfied for a PIN code */
    private boolean CheckPINPolicy(byte[] pin_buffer, short pin_offset, byte pin_size) {
        if ((pin_size < PIN_MIN_SIZE) || (pin_size > PIN_MAX_SIZE))
            return false;
        return true;
    }
    
    private void resetLockThenThrow(short ErrorCode, boolean destroy_object){
        //destroy object if the error happened during secret object creation
        if (destroy_object){
            om_secrets.destroyObject(OM_TYPE, lock_id, true);
        }
        // log
        logger.updateLog(lock_ins, lock_id, lock_id_pubkey, ErrorCode);
        // Release lock
        lock_enabled = false;
        lock_ins= 0x00;
        lock_lastop= 0x00;
        lock_transport_mode= 0x00;
        lock_obj_offset = 0x00;
        lock_obj_size = 0x00;
        // throws exception
        ISOException.throwIt(ErrorCode);
    }
    
    /** Erase all user data */
    private boolean resetToFactory(){
        
        //TODO        
        // logs
        // currently, we do NOT erase logs, but we add an entry for the reset
        logger.createLog(INS_RESET_TO_FACTORY, (short)-1, (short)-1, (short)0x0000 );
        
        // reset all secrets in store
        om_secrets.resetObjectManager(true);
        
        // reset NFC policy to enabled
        nfc_policy = NFC_ENABLED;

        // reset card label
        card_label_size=0;
        Util.arrayFillNonAtomic(card_label, (short)0, (short)card_label.length, (byte)0);
        
        // setup
        pin.update(PIN_INIT_VALUE, (short) 0, (byte) PIN_INIT_VALUE.length);
        setupDone=false;
        
        // update log
        logger.updateLog(INS_RESET_TO_FACTORY, (short)-1, (short)-1, (short)0x9000 );
        
        return true;
    }
    
    /****************************************
     *              APDU handlers           *
     ****************************************/   
    
    /** 
     * DEPRECATED: use generateRandomSecret() instead
     * This function generates a master seed randomly within the SeedKeeper
     * 
     * ins: 0xA0
     * p1: seed size in byte (between 16-64)
     * p2: export_rights
     * data: [ label_size(1b) | label  ]
     * return: [ id(2b) | fingerprint(4b) ]
     */
    private short generateMasterseed(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        // log operation
        logger.createLog(INS_GENERATE_MASTERSEED, (short)-1, (short)-1, (short)0x0000);
        
        byte seed_size= buffer[ISO7816.OFFSET_P1];
        if ((seed_size < MIN_SEED_SIZE) || (seed_size > MAX_SEED_SIZE) )
            ISOException.throwIt(SW_INCORRECT_P1);
        
        // we don't check export/usage rights, bits outside mask are just ignored
        byte export_rights = (byte)(buffer[ISO7816.OFFSET_P2]&SECRET_EXPORT_MASK);   
        // if ((export_rights < SECRET_EXPORT_FORBIDDEN) || (export_rights > SECRET_EXPORT_SECUREONLY) )
        //     ISOException.throwIt(SW_INCORRECT_P2);
    
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short recv_offset = (short)0;
        short label_size= Util.makeShort((byte) 0x00, buffer[buffer_offset]);
        buffer_offset++;
        if (label_size> MAX_LABEL_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
    
        // common data_header: [ type(1b) | origin(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | export_pubkey_counter(1b) | fingerprint(4b) | label_size(1b) | label ]
        // SECRET_TYPE_MASTER_SEED: [ size(1b) | seed_blob ]
        recvBuffer[SECRET_OFFSET_TYPE]= SECRET_TYPE_MASTER_SEED;
        recvBuffer[SECRET_OFFSET_ORIGIN]= SECRET_ORIGIN_ONCARD;
        recvBuffer[SECRET_OFFSET_EXPORT_CONTROL]= export_rights;
        recvBuffer[SECRET_OFFSET_EXPORT_NBPLAIN]= (byte)0;
        recvBuffer[SECRET_OFFSET_EXPORT_NBSECURE]= (byte)0;
        recvBuffer[SECRET_OFFSET_EXPORT_COUNTER]= (byte)0;
        recvBuffer[SECRET_OFFSET_SUBTYPE]= (byte)0;
        recvBuffer[SECRET_OFFSET_RFU2]= (byte)0;
        recvBuffer[SECRET_OFFSET_LABEL_SIZE]= (byte) (label_size & 0x7f);
        Util.arrayFillNonAtomic(recvBuffer, SECRET_OFFSET_FINGERPRINT, SECRET_FINGERPRINT_SIZE, (byte)0);
        Util.arrayCopyNonAtomic(buffer, buffer_offset, recvBuffer, SECRET_OFFSET_LABEL, label_size);
        recv_offset= (short) (SECRET_HEADER_SIZE + label_size);
        
        // generate seed
        buffer[(short)0]= seed_size;
        randomData.generateData(buffer,(short)(1), seed_size);
        //fingerprint
        sha256.reset();
        sha256.doFinal(buffer, (short)0, (short)(seed_size+1), buffer, (short)(seed_size+1));
        Util.arrayCopyNonAtomic(buffer, (short)(seed_size+1), recvBuffer, SECRET_OFFSET_FINGERPRINT, SECRET_FINGERPRINT_SIZE);
        //pad and encrypt seed for storage 
        short padsize= (short) (AES_BLOCKSIZE - ((seed_size+1)%AES_BLOCKSIZE) );
        Util.arrayFillNonAtomic(buffer, (short)(1+seed_size), padsize, (byte)padsize);//padding
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_ENCRYPT);
        short enc_size= om_aes128_ecb.doFinal(buffer, (short)0, (short)(1+seed_size+padsize), recvBuffer, recv_offset);
        recv_offset+=enc_size; //recv_offset+= seed_size;
        
        // Check if object exists
        while (om_secrets.exists(OM_TYPE, om_nextid)){
            om_nextid++;
        }
        short base= om_secrets.createObject(OM_TYPE, om_nextid, recv_offset, false);
        om_secrets.setObjectData(base, (short)0, recvBuffer, (short)0, recv_offset);
        
        // log operation (fill log as soon as available)
        logger.updateLog(INS_GENERATE_MASTERSEED, om_nextid, (short)-1, (short)0x9000);
        
        // Fill the buffer
        Util.setShort(buffer, (short) 0, om_nextid);
        Util.arrayCopyNonAtomic(recvBuffer, SECRET_OFFSET_FINGERPRINT, buffer, (short)2, SECRET_FINGERPRINT_SIZE);
        om_nextid++;
        
        // TODO: sign id with authentikey?
        // Send response
        return (short)(2+SECRET_FINGERPRINT_SIZE);
    }
    
    /** 
     * DEPRECATED: use generateRandomSecret() instead
     * This function generates a 2FA-secret randomly within the SeedKeeper
     * 
     * ins: AE
     * p1: 0x00
     * p2: export_rights
     * data: [ label_size(1b) | label  ]
     * return: [ id(2b) | fingerprint(4b) ]
     */
    private short generate2FASecret(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        // log operation
        logger.createLog(INS_GENERATE_2FA_SECRET, (short)-1, (short)-1, (short)0x0000);
        
        // we don't check export/usage rights, bits outside mask are just ignored
        byte export_rights = (byte)(buffer[ISO7816.OFFSET_P2]&SECRET_EXPORT_MASK);
        // if ((export_rights < SECRET_EXPORT_FORBIDDEN) || (export_rights > SECRET_EXPORT_SECUREONLY) )
        //     ISOException.throwIt(SW_INCORRECT_P2);
    
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short recv_offset = (short)0;
        short label_size= Util.makeShort((byte) 0x00, buffer[buffer_offset]);
        buffer_offset++;
        if (label_size> MAX_LABEL_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
    
        // common data_header: [ type(1b) | origin(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | export_pubkey_counter(1b) | fingerprint(4b) | label_size(1b) | label ]
        // SECRET_TYPE_2FA: [ size(1b) | 2FA_secret_blob ]
        recvBuffer[SECRET_OFFSET_TYPE]= SECRET_TYPE_2FA;
        recvBuffer[SECRET_OFFSET_ORIGIN]= SECRET_ORIGIN_ONCARD;
        recvBuffer[SECRET_OFFSET_EXPORT_CONTROL]= export_rights;
        recvBuffer[SECRET_OFFSET_EXPORT_NBPLAIN]= (byte)0;
        recvBuffer[SECRET_OFFSET_EXPORT_NBSECURE]= (byte)0;
        recvBuffer[SECRET_OFFSET_EXPORT_COUNTER]= (byte)0;
        recvBuffer[SECRET_OFFSET_SUBTYPE]= (byte)0;
        recvBuffer[SECRET_OFFSET_RFU2]= (byte)0;
        recvBuffer[SECRET_OFFSET_LABEL_SIZE]= (byte) (label_size & 0x7f);
        Util.arrayFillNonAtomic(recvBuffer, SECRET_OFFSET_FINGERPRINT, SECRET_FINGERPRINT_SIZE, (byte)0);
        Util.arrayCopyNonAtomic(buffer, buffer_offset, recvBuffer, SECRET_OFFSET_LABEL, label_size);
        recv_offset= (short) (SECRET_HEADER_SIZE + label_size);
        
        // generate random bytes
        buffer[(short)0]= SIZE_2FA;
        randomData.generateData(buffer,(short)(1), SIZE_2FA);
        //fingerprint
        sha256.reset();
        sha256.doFinal(buffer, (short)0, (short)(SIZE_2FA+1), buffer, (short)(SIZE_2FA+1));
        Util.arrayCopyNonAtomic(buffer, (short)(SIZE_2FA+1), recvBuffer, SECRET_OFFSET_FINGERPRINT, SECRET_FINGERPRINT_SIZE);
        //pad and encrypt seed for storage 
        short padsize= (short) (AES_BLOCKSIZE - ((SIZE_2FA+1)%AES_BLOCKSIZE) );
        Util.arrayFillNonAtomic(buffer, (short)(1+SIZE_2FA), padsize, (byte)padsize);//padding
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_ENCRYPT);
        short enc_size= om_aes128_ecb.doFinal(buffer, (short)0, (short)(1+SIZE_2FA+padsize), recvBuffer, recv_offset);
        recv_offset+=enc_size; //recv_offset+= SIZE_2FA;
        
        // Check if object exists
        while (om_secrets.exists(OM_TYPE, om_nextid)){
            om_nextid++;
        }
        short base= om_secrets.createObject(OM_TYPE, om_nextid, recv_offset, false);
        om_secrets.setObjectData(base, (short)0, recvBuffer, (short)0, recv_offset);
        
        // log operation (todo: fill log as soon as available)
        logger.updateLog(INS_GENERATE_2FA_SECRET, om_nextid, (short)-1, (short)0x9000);
        
        // Fill the buffer
        Util.setShort(buffer, (short) 0, om_nextid);
        Util.arrayCopyNonAtomic(recvBuffer, SECRET_OFFSET_FINGERPRINT, buffer, (short)2, SECRET_FINGERPRINT_SIZE);
        om_nextid++;
        
        // TODO: sign id with authentikey?
        // Send response
        return (short)(2+SECRET_FINGERPRINT_SIZE);
    }

    /** 
     * This function generates a secret randomly within the SeedKeeper.
     * Secret_type should be in [SECRET_TYPE_MASTER_SEED, SECRET_TYPE_MASTER_PASSWORD, SECRET_TYPE_PRIVKEY, SECRET_TYPE_KEY]
     * Secret_subtype allows to provide more context for the secret, e.g. the type of the key (AES/DES or Secp256k1...). 
     * if flag_save_enropy == 0x01: save a 'proof' that the secret used the external entropy provided
     * Entropy is random data provided by the user and used in the secret random generation. 
     * Entropy size should be <= to the secret size to be generated
     * 
     * ins: 0xA3
     * p1: secret size in byte (between 16-64)
     * p2: export_rights
     * data: [ secret_type(1b) | secret_subtype(1b) | flag_save_enropy(1b) | label_size(1b) | label | entropy_size(1b) | entropy]
     * return: [ id(2b) | fingerprint(4b) ]
     */
    private short generateRandomSecret(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        // log operation
        logger.createLog(INS_GENERATE_RANDOM_SECRET, (short)-1, (short)-1, (short)0x0000);
        
        byte secret_size= buffer[ISO7816.OFFSET_P1];
        if ((secret_size < MIN_RANDOM_SIZE) || (secret_size > MAX_RANDOM_SIZE) )
            ISOException.throwIt(SW_INCORRECT_P1);
    
        // we don't check export/usage rights, bits outside mask are just ignored
        byte export_rights = (byte)(buffer[ISO7816.OFFSET_P2]&SECRET_EXPORT_MASK);
        // if ((export_rights < SECRET_EXPORT_FORBIDDEN) || (export_rights > SECRET_EXPORT_SECUREONLY))
        //     ISOException.throwIt(SW_INCORRECT_P2);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft<4)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        short buffer_offset = ISO7816.OFFSET_CDATA;
        byte secret_type = buffer[buffer_offset];
        buffer_offset++;
        byte secret_subtype = buffer[buffer_offset];
        buffer_offset++;
        byte flag_save_entropy = buffer[buffer_offset];
        buffer_offset++;
        short label_size= Util.makeShort((byte) 0x00, buffer[buffer_offset]);
        buffer_offset++;
        bytesLeft-=(short)4;
        if (label_size> MAX_LABEL_SIZE)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (bytesLeft<= label_size) // also check for next byte entropy_size
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // check type
        if ((secret_type != SECRET_TYPE_MASTER_SEED) &&
            (secret_type != SECRET_TYPE_MASTER_PASSWORD) &&
            (secret_type != SECRET_TYPE_2FA) &&
            (secret_type != SECRET_TYPE_PRIVKEY) &&
            (secret_type != SECRET_TYPE_KEY)){
            ISOException.throwIt(SW_WRONG_SECRET_TYPE);
        }

        // TODO: check size for all types
        if (secret_type == SECRET_TYPE_MASTER_SEED){
            if ((secret_size < MIN_SEED_SIZE) || (secret_size > MAX_SEED_SIZE) )
                ISOException.throwIt(SW_INCORRECT_P1);
        }
        
        // compute object size
        short header_size = (short)(SECRET_HEADER_SIZE + label_size);
        short secret_plain_size = (short)(1+secret_size); // all secret have the format [size(1b) | secret]
        short pad_size = (short) (AES_BLOCKSIZE - (secret_plain_size)%AES_BLOCKSIZE);
        short obj_size = (short) (header_size + secret_plain_size + pad_size);

        // Check if object exists
        while (om_secrets.exists(OM_TYPE, om_nextid)){
            om_nextid++;
        }
        // create object
        short obj_base= om_secrets.createObject(OM_TYPE, om_nextid, obj_size, false);

        // save header to object
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_TYPE, secret_type);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_ORIGIN, SECRET_ORIGIN_ONCARD);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_CONTROL, export_rights);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBPLAIN, (byte)0);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE, (byte)0);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_COUNTER, (byte)0);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_SUBTYPE, secret_subtype);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_RFU2, (byte)0);
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_LABEL_SIZE, (byte) (label_size & 0x7f));
        om_secrets.setObjectData(obj_base, SECRET_OFFSET_LABEL, buffer, buffer_offset, label_size);

        // copy external entropy to recvBuffer
        // recvBuffer map: [size_entropy(1b) | entropy_ext | entropy_gen(secret_size) | size_secret(1b) | secret(secret_size) |  fingerprint(4b)]
        buffer_offset+= label_size;
        bytesLeft-= label_size;
        byte entropy_size = buffer[buffer_offset];
        if (entropy_size > secret_size)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        buffer_offset++;
        bytesLeft--;
        if (bytesLeft < entropy_size)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        Util.arrayCopyNonAtomic(buffer, buffer_offset, recvBuffer, (short)1, entropy_size); // leave space for type and size if needed 
        // generate random internal entropy
        randomData.generateData(recvBuffer, (short)(1+entropy_size), (short)secret_size);
        // secret is the sha512([external_entropy | internal_entropy]), trimmed to first secret_size bytes if secret_size<64
        sha512.reset();
        sha512.doFinal(recvBuffer, (short)1, (short)(entropy_size+secret_size), recvBuffer, (short)(1+entropy_size+secret_size+1));
        // set secret subtype & size
        short secret_offset = (short) (1+entropy_size+secret_size); 
        recvBuffer[secret_offset] = secret_size;

        // compute fingerprint
        sha256.reset();
        sha256.doFinal(recvBuffer, secret_offset, (short)(1+secret_size), recvBuffer, (short)(secret_offset+1+secret_size));
        // set fingerprint in object
        om_secrets.setObjectData(obj_base, SECRET_OFFSET_FINGERPRINT, recvBuffer, (short)(secret_offset+1+secret_size), SECRET_FINGERPRINT_SIZE);

        //pad and encrypt secret for storage (padding overwrites partially the fingerprint)
        Util.arrayFillNonAtomic(recvBuffer, (short)(secret_offset+1+secret_size), pad_size, (byte)pad_size);//padding
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_ENCRYPT);
        short enc_size= om_aes128_ecb.doFinal(recvBuffer, secret_offset, (short)(1+secret_size+pad_size), recvBuffer, secret_offset); // asset(enc_size == secret_plain_size+pad_size)
        // set encrypted secret in object
        om_secrets.setObjectData(obj_base, (short)(SECRET_HEADER_SIZE+label_size), recvBuffer, secret_offset, enc_size);
        // overwrite plain secret
        Util.arrayFillNonAtomic(recvBuffer, secret_offset, (short)(1+secret_size), (byte)0);
        
        // log operation
        logger.updateLog(INS_GENERATE_RANDOM_SECRET, om_nextid, (short)-1, (short)0x9000);

        // Fill the return buffer
        Util.setShort(buffer, (short) 0, om_nextid);
        om_secrets.getObjectData(obj_base, SECRET_OFFSET_FINGERPRINT, buffer, (short)2, SECRET_FINGERPRINT_SIZE);
        om_nextid++;

        // if requested, we can save entropy as a secret, this can be used to show that secret was generated by combining external & internal entropy)
        if (flag_save_entropy == (byte)0x01){

            // create partial log
            logger.createLog(INS_GENERATE_RANDOM_SECRET, (short)-1, (short)-1, (short)0x0000);

            header_size = (short)(SECRET_HEADER_SIZE + ENTROPY_LABEL.length);
            secret_plain_size = (short)(1+entropy_size+secret_size); // entropy has a key format [size(1b) | secret]
            pad_size = (short) (AES_BLOCKSIZE - (secret_plain_size)%AES_BLOCKSIZE);
            obj_size = (short) (header_size + secret_plain_size + pad_size);
            short secret_id= (short)(om_nextid-1); // reference to random secret previously created

            // Check if object exists
            while (om_secrets.exists(OM_TYPE, om_nextid)){
                om_nextid++;
            }
            // create object
            obj_base= om_secrets.createObject(OM_TYPE, om_nextid, obj_size, false);
            
            // save header to object
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_TYPE, SECRET_TYPE_KEY);
            // TODO: add subtype
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_ORIGIN, SECRET_ORIGIN_ONCARD);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_CONTROL, export_rights);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBPLAIN, (byte)0);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE, (byte)0);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_COUNTER, (byte)0);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_SUBTYPE, SECRET_SUBTYPE_ENTROPY);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_RFU2, (byte)0);
            om_secrets.setObjectByte(obj_base, SECRET_OFFSET_LABEL_SIZE, (byte)ENTROPY_LABEL.length);
            om_secrets.setObjectData(obj_base, SECRET_OFFSET_LABEL, ENTROPY_LABEL, (short)0, (short)ENTROPY_LABEL.length);

            // entropy is located in contiguous memory in recvBuffer 
            // size_entropy(1b) | external_entropy(entropy_size) | internal_entropy(secret_size)]
            //Util.setShort(recvBuffer, (short)0, (short)(entropy_size+secret_size)); // up to 128 bytes
            short size= (short)(entropy_size+secret_size);
            recvBuffer[(short)0] = (byte)(size & 0xff); // up to 128 bytes
            // compute fingerprint
            sha256.reset();
            sha256.doFinal(recvBuffer, (short)0, (short)(1+entropy_size+secret_size), recvBuffer, (short)(1+entropy_size+secret_size));
            // set fingerprint in object
            om_secrets.setObjectData(obj_base, SECRET_OFFSET_FINGERPRINT, recvBuffer, (short)(1+entropy_size+secret_size), SECRET_FINGERPRINT_SIZE);

            //pad and encrypt secret for storage (padding overwrites partially the fingerprint)
            Util.arrayFillNonAtomic(recvBuffer, (short)(1+entropy_size+secret_size), pad_size, (byte)pad_size);//padding
            om_aes128_ecb.init(om_encryptkey, Cipher.MODE_ENCRYPT);
            enc_size= om_aes128_ecb.doFinal(recvBuffer, (short)0, (short)(1+entropy_size+secret_size+pad_size), recvBuffer, (short)0); // asset(enc_size == secret_plain_size+pad_size)
            // set encrypted secret in object
            om_secrets.setObjectData(obj_base, (short)(SECRET_HEADER_SIZE+ENTROPY_LABEL.length), recvBuffer, (short)0, enc_size);
            // overwrite plain secret
            Util.arrayFillNonAtomic(recvBuffer, (short)0, (short)(1+entropy_size+secret_size), (byte)0);

            // log operation
            logger.updateLog(INS_GENERATE_RANDOM_SECRET, om_nextid, (short)-1, (short)0x9000);
        
            // Fill the return buffer
            Util.setShort(buffer, (short)(2+SECRET_FINGERPRINT_SIZE), om_nextid);
            om_secrets.getObjectData(obj_base, SECRET_OFFSET_FINGERPRINT, buffer, (short)(2+SECRET_FINGERPRINT_SIZE+2), SECRET_FINGERPRINT_SIZE);
            om_nextid++;

            // Send response
            return (short)(4+2*SECRET_FINGERPRINT_SIZE);
        }
        // Send response
        return (short)(2+SECRET_FINGERPRINT_SIZE);
    }

    
    /** 
     * This function derives and export a secret (password) from a master password and provided salt.
     * Derivation is done using HMAC-SHA512 using the salt as key and master password as message.
     * Currently, only plaintext export is suported.
     * 
     * ins: AA
     * p1: 0x01 (plain import) or todo: secure export
     * p2: 0x00
     * data: [ master_password_sid(2b) | salt_size(1b) | salt_used_for_derivation (max 128 bytes) ]
     * return: [ derived_data_size(2b) | derived_data | sig_size(2b) | authentikey_sig]
     */
    private short deriveMasterPassword(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // get id
        short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytes_left<3){
            ISOException.throwIt(SW_INVALID_PARAMETER);}
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short lock_id= Util.getShort(buffer, buffer_offset);
        buffer_offset+=2;

        // get salt data (should be max 128 bytes)
        short salt_size = Util.makeShort((byte) 0x00, buffer[buffer_offset]);
        buffer_offset++;
        if (bytes_left<(short)(3+salt_size)){
            ISOException.throwIt(SW_INVALID_PARAMETER);}
        
        // currently, we do not support secure export, only plaintext
        short lock_id_pubkey = (short)-1;

        // log operation to be updated later
        logger.createLog(INS_DERIVE_MASTER_PASSWORD, lock_id, lock_id_pubkey, (short)0x0000);
                
        // get master_password base address
        short base= om_secrets.getBaseAddress(OM_TYPE, lock_id);
        if (base==(short)0xFFFF){
            logger.updateLog(INS_DERIVE_MASTER_PASSWORD, lock_id, lock_id_pubkey, SW_OBJECT_NOT_FOUND);
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        }
        short obj_size= om_secrets.getSizeFromAddress(base);
        //om_secrets.getObjectData(base, (short)0, recvBuffer, (short)0, obj_size);

        // check type is correct
        byte secret_type = om_secrets.getObjectByte(base, SECRET_OFFSET_TYPE);   
        if (secret_type!=SECRET_TYPE_MASTER_PASSWORD){
            logger.updateLog(INS_DERIVE_MASTER_PASSWORD, lock_id, lock_id_pubkey, SW_WRONG_SECRET_TYPE);
            ISOException.throwIt(SW_WRONG_SECRET_TYPE);
        }
        // check export policy, currently we only support plaintext export
        byte export_policy = om_secrets.getObjectByte(base, SECRET_OFFSET_EXPORT_CONTROL);
        if ((export_policy & SECRET_EXPORT_MASK) != SECRET_EXPORT_ALLOWED){
            logger.updateLog(INS_BIP32_GET_EXTENDED_KEY, lock_id, lock_id_pubkey, SW_EXPORT_NOT_ALLOWED);
            ISOException.throwIt(SW_EXPORT_NOT_ALLOWED);
        }
        // update derivation counter
        byte counter = om_secrets.getObjectByte(base, SECRET_OFFSET_EXPORT_COUNTER);   
        counter++; // incremented each time we derive a new key
        om_secrets.setObjectByte(base, SECRET_OFFSET_EXPORT_COUNTER, counter);   

        // copy encrypted secret to recv_buffer
        short label_size= Util.makeShort((byte)0, om_secrets.getObjectByte(base, SECRET_OFFSET_LABEL_SIZE));
        short base_offset = (short)(SECRET_HEADER_SIZE+label_size);
        short base_remaining= (short)(obj_size-base_offset);
        om_secrets.getObjectData(base, base_offset, recvBuffer, (short)0, base_remaining);

        // decrypt secret in same buffer to recover master password
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
        short dec_size= om_aes128_ecb.update(recvBuffer, (short)0, base_remaining, recvBuffer, (short)0);
        byte pad_size= recvBuffer[(short)(dec_size-1)];
        dec_size-=pad_size;
        short password_size = recvBuffer[(short)0];
        if (password_size>=dec_size){ // password_size should be < dec_size
            ISOException.throwIt(SW_INVALID_PARAMETER);}

        // compute hmac(key, message), where key = salt and message = master password
        short hmac_size=HmacSha512.computeHmacSha512(buffer, buffer_offset, salt_size, recvBuffer, (short)1, password_size, buffer, (short) 2);
        Util.setShort(buffer, (short)0, hmac_size); //should be 64bytes           

        // erase master password copy in revBuffer
        Util.arrayFillNonAtomic(recvBuffer, (short)0, dec_size, (byte)0);

        // finalize sign with authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(2+hmac_size), buffer, (short)(2+hmac_size+2));
        Util.setShort(buffer, (short)(2+hmac_size), sign_size);
                  
        // update log
        logger.updateLog(INS_DERIVE_MASTER_PASSWORD, lock_id, lock_id_pubkey, ISO7816.SW_NO_ERROR);

        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [data_size(2b) | data | sigsize(2) | sig]
        return (short)(2+hmac_size+2+sign_size);
    }

    /**
     * The function computes the Bip32 extended key derived from the master key and returns either the 
     * 32-bytes x-coordinate of the public key, or the 32-bytes private key, signed by the authentikey.
     * 
     * The Path for the derivation is provided in the apdu data.
     * 
     * ins: 0x6D
     * p1: depth of the extended key (master is depth 0, m/i is depht 1). Max depth is 10
     * p2: option_flags (masks):
     *      0x80: (deprecated: reset the bip32 cache memory)
     *      0x40: (deprecated: optimize non-hardened child derivation)
     *      0x20: (deprecated: flag whether to store key as object)
     *      0x01: if set, use secure export (currently not supported!), otherwise use plain export
     *      0x02: if set, return privkey bytes, else public key
     *      0x04: (RFU) if set, add final BIP85 HMAC derivation (currently not supported!)
     * 
     * data: [path_bytes(4*depth) | sid(2b) | sid_pubkey(2b)] where:
     *      path_bytes is the index path from master to extended key (m/i/j/k/...). 4 bytes per index
     *      sid is the id of the Masterseed to use
     *      sid_pubkey (RFU): id of a pubkey for secure (encrypted) export (currently not supported).
     * 
     * returns: [chaincode(32b) | coordx_size(2b) | coordx | sig_size(2b) | sig | sig_size(2b) | sig2] if (option_flags & 0x02 == 0x00) BIP32 pubkey
     *          [chaincode(32b) | privkey_bytes(2b) | privkey | sig_size(2b) | sig | sig_size(2b) | sig2] if (option_flags & 0x02 == 0x02) BIP32 privkey
     *          [entropy_size(2b) | entropy_bytes(64) | sig_size(2b) | sig | sig_size(2b) | sig2] if (option_flags & 0x04 == 0x04) BIP85
     * 
     * */
    private short getBIP32ExtendedKey(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // input 
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        
        byte bip32_depth = buffer[ISO7816.OFFSET_P1];
        if ((bip32_depth < 0) || (bip32_depth > BIP32_MAX_DEPTH) )
            ISOException.throwIt(SW_INCORRECT_P1);
        if (bytesLeft < (short)(4*bip32_depth+2)) // path + sid
            ISOException.throwIt(SW_INVALID_PARAMETER);
        
        // P2 option flags
        byte opts = buffer[ISO7816.OFFSET_P2]; 
        // if ((opts & 0x01)==0x01)
        //     ISOException.throwIt(SW_UNSUPPORTED_FEATURE); // secure export is not supported currently

        // start logging
        logger.createLog(INS_BIP32_GET_EXTENDED_KEY, (short)-1, (short)-1, (short)0x0000);

        // get masterseed sid
        short path_offset = ISO7816.OFFSET_CDATA;
        short sid = Util.getShort(buffer, (short)(path_offset + 4*bip32_depth));
        short obj_base = om_secrets.getBaseAddress(OM_TYPE, sid);
        if (obj_base==(short)0xFFFF){
            logger.updateLog(INS_BIP32_GET_EXTENDED_KEY, sid, (short)-1, SW_OBJECT_NOT_FOUND);
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        }
        // check type, only types containing a masterseed are supported
        byte secret_type = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_TYPE);
        if (secret_type != SECRET_TYPE_MASTER_SEED){
            logger.updateLog(INS_BIP32_GET_EXTENDED_KEY, sid, (short)-1, SW_WRONG_SECRET_TYPE);
            ISOException.throwIt(SW_WRONG_SECRET_TYPE);
        }
        // check export policy, currently we only support plaintext export
        byte export_policy = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_CONTROL);
        if ((export_policy & SECRET_EXPORT_MASK) != SECRET_EXPORT_ALLOWED){
            logger.updateLog(INS_BIP32_GET_EXTENDED_KEY, sid, (short)-1, SW_EXPORT_NOT_ALLOWED);
            ISOException.throwIt(SW_EXPORT_NOT_ALLOWED);
        }
        // increment usage counter
        byte counter = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_COUNTER);
        counter++;
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_COUNTER, counter);

        // copy encrypted masterseed to recvbuffer
        short obj_size= om_secrets.getSizeFromAddress(obj_base);
        byte label_size = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_LABEL_SIZE);
        short secret_offset = (short) (SECRET_HEADER_SIZE + label_size);
        om_secrets.getObjectData(obj_base, secret_offset, recvBuffer, (short)0, (short)(obj_size-secret_offset));
        // decrypt masterseed
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
        short dec_size= om_aes128_ecb.doFinal(recvBuffer, (short)0, (short)(obj_size-secret_offset), recvBuffer, (short)0);
        byte masterseed_size= recvBuffer[0]; 
        // recvBuffer map: [masterseed_size(1b) | masterseed]

        // derive master key from masterseed
        HmacSha512.computeHmacSha512(BITCOIN_SEED, (short)0, (short)BITCOIN_SEED.length, recvBuffer, (short)1, (short)masterseed_size, recvBuffer, BIP32_OFFSET_PARENT_KEY);
        // recvBuffer map: [ garbage(33b) | bip32_masterkey(32b) | bip32_masterchaincode(32b)]
        Util.arrayCopyNonAtomic(recvBuffer, (short)65, recvBuffer, (short)0, BIP32_KEY_SIZE);
        recvBuffer[BIP32_OFFSET_PARENT_SEPARATOR]= 0x00; // separator, also facilitate HMAC derivation
        // recvBuffer map: [ bip32_masterchaincode(32b) | 0x00(1b) | bip32_masterkey(32b) | bip32_masterchaincode(32b)]
        
        // The method uses a temporary buffer recvBuffer to store the parent and extended key object data:
        // recvBuffer=[ parent_chain_code (32b) | 0x00 | parent_key (32b) | buffer(index)(32b) | current_extended_key(32b) | current_chain_code(32b) | parent_pubkey(65b)]
        // parent_pubkey(65b)= [compression_byte(1b) | coord_x (32b) | coord_y(32b)]
        
        
        // path indexes are stored in buffer starting at ISO7816.OFFSET_CDATA offset
        // iterate on indexes provided 
        for (byte i=0; i<bip32_depth; i++){
             path_offset = (short)(ISO7816.OFFSET_CDATA+4*i);

            // normal or hardened child?
            byte msb= buffer[path_offset];
            if ((msb & 0x80)!=0x80){ // normal child

                // todo: for BIP85, only hardened child is allowed
                
                // compute coord x from privkey 
                bip32_extendedkey.setS(recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE);
                keyAgreement.init(bip32_extendedkey);
                
                // keyAgreement.generateSecret() recovers X and Y coordinates
                keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, recvBuffer, BIP32_OFFSET_PUB); //pubkey in uncompressed form
                boolean parity= ((recvBuffer[(short)(BIP32_OFFSET_PUBY+31)]&0x01)==0);
                byte compbyte= (parity)?(byte)0x02:(byte)0x03; 
                
                // compute HMAC of compressed pubkey + index
                recvBuffer[BIP32_OFFSET_PUB]= compbyte;
                Util.arrayCopyNonAtomic(buffer, path_offset, recvBuffer, BIP32_OFFSET_PUBY, (short)4);
                HmacSha512.computeHmacSha512(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_KEY_SIZE, recvBuffer, BIP32_OFFSET_PUB, (short)(1+BIP32_KEY_SIZE+4), recvBuffer, BIP32_OFFSET_CHILD_KEY);
            }
            else { // hardened child
                recvBuffer[BIP32_OFFSET_PARENT_SEPARATOR]= 0x00;
                Util.arrayCopyNonAtomic(buffer, path_offset, recvBuffer, BIP32_OFFSET_INDEX, (short)4);
                HmacSha512.computeHmacSha512(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_KEY_SIZE, recvBuffer, BIP32_OFFSET_PARENT_SEPARATOR, (short)(1+BIP32_KEY_SIZE+4), recvBuffer, BIP32_OFFSET_CHILD_KEY);
            }

            // addition with parent_key...
            // First check that parse256(IL) < SECP256K1_R
            if(!Biginteger.lessThan(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE)){
                logger.updateLog(INS_BIP32_GET_EXTENDED_KEY, sid, (short)-1, SW_BIP32_DERIVATION_ERROR);
                ISOException.throwIt(SW_BIP32_DERIVATION_ERROR);
            }
            // add parent_key (mod SECP256K1_R)
            if(Biginteger.add_carry(recvBuffer, BIP32_OFFSET_CHILD_KEY, recvBuffer, (short) (BIP32_KEY_SIZE+1), BIP32_KEY_SIZE)){
                // in case of final carry, we must substract SECP256K1_R
                // we have IL<SECP256K1_R and parent_key<SECP256K1_R, so IL+parent_key<2*SECP256K1_R
                Biginteger.subtract(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE); 
            }else{
                // in the unlikely case where SECP256K1_R<=IL+parent_key<2^256
                if(!Biginteger.lessThan(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE)){
                    Biginteger.subtract(recvBuffer, BIP32_OFFSET_CHILD_KEY, Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_R, BIP32_KEY_SIZE);
                }
                // check that value is not 0
                if(Biginteger.equalZero(recvBuffer, BIP32_OFFSET_CHILD_KEY, BIP32_KEY_SIZE)){
                    logger.updateLog(INS_BIP32_GET_EXTENDED_KEY, sid, (short)-1, SW_BIP32_DERIVATION_ERROR);
                    ISOException.throwIt(SW_BIP32_DERIVATION_ERROR);
                }
            }

            // at this point, recvBuffer contains the extended key at depth i
            recvBuffer[BIP32_OFFSET_PUB]=0x04;
            // copy privkey & chain code in parent's offset
            Util.arrayCopyNonAtomic(recvBuffer, BIP32_OFFSET_CHILD_CHAINCODE, recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_KEY_SIZE); // chaincode
            Util.arrayCopyNonAtomic(recvBuffer, BIP32_OFFSET_CHILD_KEY, recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE); // extended_key
            recvBuffer[BIP32_OFFSET_PARENT_SEPARATOR]=0x00;            
        } // end for

        // at this point, recvBuffer contains a copy of the chaincode & last extended private key
        // instantiate elliptic curve with last extended key
        bip32_extendedkey.setS(recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE);
        
        // BIP85 option flag
        if ((opts & 0x04)==0x04){
            // compute final HmacSha512
            HmacSha512.computeHmacSha512(BIP85_SALT, (short)0, (short)BIP85_SALT.length, recvBuffer, BIP32_OFFSET_PARENT_KEY, BIP32_KEY_SIZE, buffer, (short)2);
            Util.setShort(buffer, (short)0, (short)64);
            // clear recvBuffer
            Util.arrayFillNonAtomic(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_OFFSET_END, (byte)0);
        } else {
            // BIP32 pubkey or privkey
            // save chaincode to buffer
            Util.arrayCopyNonAtomic(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, buffer, (short)0, BIP32_KEY_SIZE); 
            // clear recvBuffer
            Util.arrayFillNonAtomic(recvBuffer, BIP32_OFFSET_PARENT_CHAINCODE, BIP32_OFFSET_END, (byte)0);
            // copy privkey or pubkey depending on option flag
            if ((opts & 0x02)==0x02){
                // export privkey directly
                bip32_extendedkey.getS(buffer, (short)34);
                Util.setShort(buffer, BIP32_KEY_SIZE, BIP32_KEY_SIZE);
            } else {
                // export pubkey
                // compute the corresponding partial public key
                keyAgreement.init(bip32_extendedkey);
                keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)33); //pubkey in uncompressed form including 0x04 byte
                Util.setShort(buffer, BIP32_KEY_SIZE, BIP32_KEY_SIZE);
            }
        }
        
        // self-sign coordx
        sigECDSA.init(bip32_extendedkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+2+BIP32_KEY_SIZE), buffer, (short)(BIP32_KEY_SIZE+BIP32_KEY_SIZE+4));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+BIP32_KEY_SIZE+2), sign_size);
        
        // coordx signed by authentikey
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size2= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+BIP32_KEY_SIZE+sign_size+4), buffer, (short)(BIP32_KEY_SIZE+BIP32_KEY_SIZE+sign_size+6));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+BIP32_KEY_SIZE+sign_size+4), sign_size2);
        
        // return x-coordinate of public key+signatures
        // the client can recover full public-key by guessing the compression value () and verifying the signature... 
        // buffer=[chaincode(32) | coordx_size(2) | coordx | sign_size(2) | self-sign | sign_size(2) | auth_sign]
        return (short)(BIP32_KEY_SIZE+BIP32_KEY_SIZE+sign_size+sign_size2+6);
        
    }// end of getBip32ExtendedKey()    

    /** 
     * This function imports a secret in plaintext/encrypted from host.
     * 
     * For SeedKeeper v0.2 and higher: 
     * During the init phase, secret_size must be provided so that exact amount of memory can be allocated.
     * This secret_size is the size that the **encrypted** secret will occupy in memory (using AES ECB with **padding**).
     * For secure import, secret is already encrypted, thus secret_size is simply the size of the encrypted secret (in bytes)
     * For plain import, secret will be encrypted in memory, so a padding of (AES_BLOCKSIZE - plain_secret_size%AES_BLOCKSIZE) must be added.
     * 
     * @param header 
     *          The header includes SECRET_HEADER_SIZE bytes of meta data plus the secret label
     * @param id_pubkey
     *          For secure import only, the short value of id of the pubkey used for import.
     *          Secret is encrypted using a symmetric key derived from the card authentikey and this pubkey via ECDH
     * @param IV
     *          For secure import only, the IV nonce used to encrypt secret (using AES in CBC mode)
     * @param secret_size
     *          Required since SeedKeeper v0.2
     * 
     * ins: 0xA1
     * p1: 0x01 (plain import) or 0x02 (secure import)
     * p2: operation (Init-Update-Final)
     * data:
     *      (init): [ header | (optional) id_pubkey(2b) | (optional) IV(16b) | secret_size(2b)]
     *      (update):[chunk_size(2b) | data_blob ]
     *      (final): [chunk_size(2b) | data_blob | (if encrypted) hmac(20b) ]
     * return:
     *      (init/update): (none) 
     *      (final) [ id(2b) | fingerprint(4b) ]
     */
    private short importSecret(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        byte transport_mode= buffer[ISO7816.OFFSET_P1];
        if (transport_mode != SECRET_EXPORT_ALLOWED && transport_mode != SECRET_EXPORT_SECUREONLY)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short obj_offset = (short)0;
        short obj_base = (short)0;
        short data_size= (short)0;// ?
        short enc_size=(short)0;
        short dec_size=(short)0;
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch (op) {
            case OP_INIT:
                // log operation to be updated later
                lock_id=(short)-1;
                lock_id_pubkey=(short)-1;
                logger.createLog(INS_IMPORT_SECRET, lock_id, lock_id_pubkey, (short)0x0000);
                
                if (bytes_left<SECRET_HEADER_SIZE)
                    ISOException.throwIt(SW_INVALID_PARAMETER); 
                
                byte type= buffer[buffer_offset];
                buffer_offset++;
                buffer_offset++; // skip 'origin'

                // we don't check export rights, bits outside mask are just ignored
                // we may add more options in future version outside this mask
                byte export_rights= (byte)(buffer[buffer_offset]&SECRET_EXPORT_MASK);
                buffer_offset++;
                buffer_offset+=7; // skip export_nb_plain, export_nb_secure, export_counter_pubkey and fingerprint
                byte subtype= buffer[buffer_offset];
                buffer_offset++;
                byte RFU2= buffer[buffer_offset];
                buffer_offset++;
                short label_size= Util.makeShort((byte) 0x00, buffer[buffer_offset]);
                if (label_size> MAX_LABEL_SIZE)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                buffer_offset++;
                bytes_left-=SECRET_HEADER_SIZE;//5;
                if (bytes_left<label_size)
                    ISOException.throwIt(SW_INVALID_PARAMETER);
                short label_offset= buffer_offset;
                buffer_offset+=label_size;
                bytes_left-=label_size;
                 
                // load public key used for secure key eschange
                if (transport_mode==SECRET_EXPORT_SECUREONLY){
                    if (bytes_left<2)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    lock_id_pubkey= Util.getShort(buffer, buffer_offset);
                    buffer_offset+=2;
                    bytes_left-=2;
                    
                    if (bytes_left<SIZE_SC_IV)//IV
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    
                    // get pubkey
                    short base_pubkey= om_secrets.getBaseAddress(OM_TYPE, lock_id_pubkey);
                    if (base_pubkey==(short)0xFFFF){
                        resetLockThenThrow(SW_OBJECT_NOT_FOUND, false);
                    }
                    short obj_pubkey_size= om_secrets.getSizeFromAddress(base_pubkey);
                    om_secrets.getObjectData(base_pubkey, (short)0, recvBuffer, (short)0, obj_pubkey_size);
                    byte pubkey_type= recvBuffer[SECRET_OFFSET_TYPE];
                    if  (pubkey_type!=SECRET_TYPE_PUBKEY){
                        resetLockThenThrow(SW_WRONG_SECRET_TYPE, false);
                    }
                    
                    // get data 
                    short pubkey_label_size= Util.makeShort((byte)0, recvBuffer[SECRET_OFFSET_LABEL_SIZE]);
                    short data_offset= (short) (SECRET_HEADER_SIZE + pubkey_label_size);
                    // initialize cipher for pubkey decryption
                    om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
                    dec_size= om_aes128_ecb.doFinal(recvBuffer, data_offset, (short)80, recvBuffer, data_offset); //size should be 65+1+padding
                    short pubkey_size= recvBuffer[data_offset];
                    if (pubkey_size != 65){
                        resetLockThenThrow(SW_INVALID_PARAMETER, false);
                    }
                    // compute shared static key 
                    keyAgreement.init(authentikey_private);        
                    keyAgreement.generateSecret(recvBuffer, (short)(data_offset+1), pubkey_size, recvBuffer, (short)0); //pubkey in uncompressed form
                    // derive secret_sessionkey & secret_mackey
                    HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, SECRET_CST_SC, (short)6, (short)6, recvBuffer, (short)33);
                    Util.arrayCopyNonAtomic(recvBuffer, (short)33, secret_sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
                    HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, SECRET_CST_SC, (short)0, (short)6, recvBuffer, (short)33);
                    secret_sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!   
                    secret_sc_aes128_cbc.init(secret_sc_sessionkey, Cipher.MODE_DECRYPT, buffer, buffer_offset, SIZE_SC_IV);
                    // init hash for mac
                    secret_sha256.reset();
                    //secret_sha256.update(buffer, ISO7816.OFFSET_CDATA, (short)(SECRET_HEADER_SIZE+label_size));
                    secret_sha256.update(buffer, ISO7816.OFFSET_CDATA, (short)(SECRET_HEADER_SIZE-1)); //do not hash the label & label_size, so thay can be modified between export and import
                    // 
                    buffer_offset+=SIZE_SC_IV;
                    bytes_left-=SIZE_SC_IV;
                }

                // new in SeedKeeper v0.2: get padded secret size (this allows to reserve memory directly)
                // if memory size is wrong, 
                if (bytes_left<2){//secret_size
                    resetLockThenThrow(SW_INVALID_PARAMETER, false);
                }
                // compute object size
                short padded_secret_size= Util.getShort(buffer, buffer_offset);
                short header_size = (short)(SECRET_HEADER_SIZE + label_size);
                short obj_size = (short)(header_size + padded_secret_size);

                // Check if object exists
                while (om_secrets.exists(OM_TYPE, om_nextid)){
                    om_nextid++;
                }
                // create object, content will be populated chunk by chunk in next steps. If an issue arises, it should be destroyed!
                // we reset initial secret memory to ensure that no info can leak if an unexpected issue arises!
                obj_base= om_secrets.createObject(OM_TYPE, om_nextid, obj_size, true);
                lock_id = om_nextid;
                om_nextid++;

                // save header to object
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_TYPE, type);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_ORIGIN, transport_mode);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_CONTROL, export_rights);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBPLAIN, (byte)0);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE, (byte)0);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_COUNTER, (byte)0);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_SUBTYPE, subtype);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_RFU2, RFU2);
                om_secrets.setObjectByte(obj_base, SECRET_OFFSET_LABEL_SIZE, (byte) (label_size & 0x7f));
                om_secrets.setObjectData(obj_base, SECRET_OFFSET_LABEL, buffer, label_offset, label_size);
                obj_offset+= (SECRET_HEADER_SIZE+label_size);

                // initialize cipher 
                om_aes128_ecb.init(om_encryptkey, Cipher.MODE_ENCRYPT);
                sha256.reset(); //for fingerprinting the secret
                
                //save state to ensure atomicity between APDU calls
                lock_ins= INS_IMPORT_SECRET;
                lock_lastop= OP_INIT;
                lock_transport_mode= transport_mode;
                lock_obj_offset= obj_offset;
                lock_obj_size= obj_size;
                lock_data_size= (short)0;
                lock_enabled = true;
                return (short)0;
                
            case OP_PROCESS:
                // check lock
                if ( (!lock_enabled) ||
                        (lock_ins!= INS_IMPORT_SECRET) ||
                        (lock_lastop!= OP_INIT && lock_lastop != OP_PROCESS))
                {
                    resetLockThenThrow(SW_LOCK_ERROR, true);
                }

                if (bytes_left<2){
                    resetLockThenThrow(SW_INVALID_PARAMETER, true);
                }

                // load the new (sensitive) data
                data_size= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;               
                bytes_left-=2;
                if (bytes_left<data_size){
                    resetLockThenThrow(SW_INVALID_PARAMETER, true);
                }
                
                if (lock_transport_mode==SECRET_EXPORT_SECUREONLY){
                    //hash the ciphertext to check hmac
                    secret_sha256.update(buffer, buffer_offset, data_size);
                    //decrypt secret
                    data_size= secret_sc_aes128_cbc.update(buffer, buffer_offset, data_size, buffer, buffer_offset);
                }
                
                // hash for fingerprinting & (re)encrypt data
                sha256.update(buffer, buffer_offset, data_size);
                enc_size= om_aes128_ecb.update(buffer, buffer_offset, data_size, buffer, buffer_offset);

                // check size
                short obj_bytes_left= (short)(lock_obj_size - lock_obj_offset);
                if (obj_bytes_left<enc_size){
                    resetLockThenThrow(SW_IMPORTED_DATA_TOO_LONG, true);
                }
                // find object then copy data to object
                obj_base = om_secrets.getBaseAddress(OM_TYPE, lock_id);
                if (obj_base==(short)0xFFFF){
                    resetLockThenThrow(SW_OBJECT_NOT_FOUND, true);
                } 
                om_secrets.setObjectData(obj_base, lock_obj_offset, buffer, buffer_offset, enc_size);

                lock_data_size+=data_size;
                lock_obj_offset+=enc_size;

                // TODO: ENSURE CONTINUITY OF OPERATIONS BETWEEN MULTIPLE APDU COMMANDS
                // Update lock state
                //lock_enabled = true;
                //lock_ins= INS_IMPORT_ENCRYPTED_SECRET;
                lock_lastop= OP_PROCESS;
                return (short)0;

            case OP_FINALIZE:
                // check lock
                if ( (!lock_enabled) || 
                        (lock_ins!= INS_IMPORT_SECRET) ||
                        (lock_lastop!= OP_INIT && lock_lastop != OP_PROCESS))
                {
                    resetLockThenThrow(SW_LOCK_ERROR, true);

                }

                if (bytes_left>=2){
                    // load the new (sensitive) data
                    buffer_offset = ISO7816.OFFSET_CDATA;
                    data_size= Util.getShort(buffer, buffer_offset);
                    buffer_offset+=2;
                    bytes_left-=2;  
                    if (bytes_left<data_size){
                        resetLockThenThrow(SW_INVALID_PARAMETER, true);
                    }  
                }else{
                    // no more data
                    data_size=(short)0;
                }
                
                short padsize=0;
                if (lock_transport_mode==SECRET_EXPORT_SECUREONLY){
                    //finalize hash the ciphertext and check hmac?
                    buffer_offset+=data_size;
                    bytes_left-=data_size;
                    if (bytes_left<1){
                        resetLockThenThrow(SW_INVALID_PARAMETER, true);
                    }
                    short hmac_size= buffer[buffer_offset];
                    buffer_offset++;
                    bytes_left--;
                    if (hmac_size !=(short)20 || bytes_left<hmac_size){
                        resetLockThenThrow(SW_INVALID_PARAMETER, true);
                    }
                    secret_sha256.doFinal(buffer, (short)(ISO7816.OFFSET_CDATA+2), data_size, buffer, (short)(buffer_offset+hmac_size) );
                    short sign_size=HmacSha160.computeHmacSha160(secret_sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, (short)(buffer_offset+hmac_size), (short)32, buffer, (short)(buffer_offset+hmac_size+32) );
                    if(Util.arrayCompare(buffer, buffer_offset, buffer, (short)(buffer_offset+hmac_size+32), (short)20) != (byte)0){
                        resetLockThenThrow(SW_SECURE_IMPORT_WRONG_MAC, true);
                    }
                    
                    buffer_offset=(short)(ISO7816.OFFSET_CDATA+2); //get back to offset with encrypted data
                    dec_size= secret_sc_aes128_cbc.doFinal(buffer, buffer_offset, data_size, buffer, buffer_offset);
                    
                    //already padded
                    padsize= buffer[(short)(buffer_offset+dec_size-1)];
                    data_size=(short)(dec_size-padsize);
                }
                else{
                    // padding
                    lock_data_size+=data_size;
                    padsize= (short) (AES_BLOCKSIZE - (lock_data_size%AES_BLOCKSIZE));
                    Util.arrayFillNonAtomic(buffer, (short)(buffer_offset+data_size), padsize, (byte)padsize);//padding
                }
                
                // finalize encrypt data
                enc_size= om_aes128_ecb.doFinal(buffer, buffer_offset, (short)(data_size+padsize), recvBuffer, (short)0);
                // check that object has enough space
                obj_bytes_left = (short)(lock_obj_size - lock_obj_offset);
                if (obj_bytes_left<enc_size){ 
                    resetLockThenThrow(SW_IMPORTED_DATA_TOO_LONG, true);
                }
                // find object then copy encrypted data
                obj_base = om_secrets.getBaseAddress(OM_TYPE, lock_id);
                if (obj_base==(short)0xFFFF){
                    resetLockThenThrow(SW_OBJECT_NOT_FOUND, true);
                } 
                // what if object size is too big?
                // secret should fit perfectly in object allocated memory, otherwise padding may be off.
                if (obj_bytes_left>enc_size){
                    // First option: destroy object & send error
                    // resetLockThenThrow(SW_IMPORTED_DATA_TOO_SHORT, true);
                    // Second option: clamp object
                    om_secrets.clampObject(obj_base, (short)(lock_obj_offset+enc_size));
                }

                om_secrets.setObjectData(obj_base, lock_obj_offset, recvBuffer, (short)0, enc_size);
                lock_obj_offset+=enc_size;

                // finalize hash to fingerprint
                sha256.doFinal(buffer, buffer_offset, data_size, buffer, (short)2);
                om_secrets.setObjectData(obj_base, SECRET_OFFSET_FINGERPRINT, buffer, (short)2, SECRET_FINGERPRINT_SIZE);

                // log operation
                logger.updateLog(INS_IMPORT_SECRET, lock_id, lock_id_pubkey, (short)0x9000);
                
                // Fill the R-APDU buffer
                Util.setShort(buffer, (short) 0, lock_id);
                
                // Release lock & send response
                lock_enabled = false;
                lock_ins= 0x00;
                lock_lastop= 0x00;
                lock_transport_mode= 0x00;
                lock_data_size= 0x00;
                return (short)(2+SECRET_FINGERPRINT_SIZE);

            default:
                ISOException.throwIt(SW_INCORRECT_P2);
        } // switch(op) 

        // Send default response
        return (short)0;    
    }
    
    /** 
     * This function exports a secret in plaintext or encrypted to the host.
     * For plaintext export, data is encrypted during transport through the Secure Channel
     * but the host has access to the data in plaintext.
     * For secure export, an encryption key is generated using ECDH.
     * For export of a Masterseed to a Satochip, the method exportSecretToSatochip() performs optimizations to reduce secret size.
     * 
     * ins: 0xA2
     * p1: 0x01 (plain export) or 0x02 (secure export)
     * p2: operation (Init-Update)
     * data: [ id(2b) | id_pubkey(2b) ]
     * return: 
     *      (init):[ id(2b) | header | IV(16b) ]
     *      (next):[data_blob_size(2b) | data_blob ]
     *      (last):[data_blob_size(2b) | data_blob | sig_size(2b) | authentikey_sig] if plain export
     *             [data_blob_size(2b) | data_blob | hmac_size(2b) | hmac(20b)] if secure export 
     */
    private short exportSecret(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        byte transport_mode= buffer[ISO7816.OFFSET_P1];
        if (transport_mode != SECRET_EXPORT_ALLOWED && transport_mode != SECRET_EXPORT_SECUREONLY)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        
        short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short obj_base=(short)0;
        short dec_size=(short)0;
        short enc_size=(short)0;
        byte label_size=(short)0;
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch (op) {
            case OP_INIT: // first request
                // set lock
                lock_ins= INS_EXPORT_SECRET;
                lock_lastop= OP_INIT;
                lock_transport_mode= transport_mode;
                lock_data_remaining= (short)0;
                lock_obj_offset= (short)0;
                lock_id_pubkey= (short)-1;
                lock_id= (short)-1;
                lock_enabled = true;
                
                // log operation to be updated later
                logger.createLog(INS_EXPORT_SECRET, lock_id, lock_id_pubkey, (short)0x0000);

                // get id
                if (bytes_left<2){
                    resetLockThenThrow(SW_INVALID_PARAMETER, false);
                }
                buffer_offset = ISO7816.OFFSET_CDATA;
                lock_id= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                
                if (lock_transport_mode==SECRET_EXPORT_SECUREONLY){
                    if (bytes_left<4){
                        resetLockThenThrow(SW_INVALID_PARAMETER, false);
                    }
                    lock_id_pubkey= Util.getShort(buffer, buffer_offset);
                    
                    // get pubkey
                    short base_pubkey= om_secrets.getBaseAddress(OM_TYPE, lock_id_pubkey);
                    if (base_pubkey==(short)0xFFFF){
                        resetLockThenThrow(SW_OBJECT_NOT_FOUND, false);
                    }
                    
                    short obj_pubkey_size= om_secrets.getSizeFromAddress(base_pubkey);
                    om_secrets.getObjectData(base_pubkey, (short)0, recvBuffer, (short)0, obj_pubkey_size);
                    byte pubkey_type= recvBuffer[SECRET_OFFSET_TYPE];
                    if  (pubkey_type!=SECRET_TYPE_PUBKEY){
                        resetLockThenThrow(SW_WRONG_SECRET_TYPE, false);
                    }
                    // update export_pubkey_counter in object
                    recvBuffer[SECRET_OFFSET_EXPORT_COUNTER]+=1;
                    om_secrets.setObjectByte(base_pubkey, SECRET_OFFSET_EXPORT_COUNTER, recvBuffer[SECRET_OFFSET_EXPORT_COUNTER]);
                    
                    // get data 
                    label_size= recvBuffer[SECRET_OFFSET_LABEL_SIZE];
                    short data_offset= (short) (SECRET_HEADER_SIZE + label_size);
                    // initialize cipher for pubkey decryption
                    om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
                    dec_size= om_aes128_ecb.doFinal(recvBuffer, data_offset, (short)80, recvBuffer, data_offset); //size should be 65+1+padding
                    short pubkey_size= recvBuffer[data_offset];
                    if (pubkey_size != 65){
                        resetLockThenThrow(SW_INVALID_PARAMETER, false);
                    }
                    
                    // compute shared static key 
                    keyAgreement.init(authentikey_private);        
                    keyAgreement.generateSecret(recvBuffer, (short)(data_offset+1), (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form
                    // derive secret_sessionkey & secret_mackey
                    HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, SECRET_CST_SC, (short)6, (short)6, recvBuffer, (short)33);
                    Util.arrayCopyNonAtomic(recvBuffer, (short)33, secret_sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
                    HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, SECRET_CST_SC, (short)0, (short)6, recvBuffer, (short)33);
                    secret_sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!   
                    randomData.generateData(secret_sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
                    secret_sc_aes128_cbc.init(secret_sc_sessionkey, Cipher.MODE_ENCRYPT, secret_sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
                }
                
                // get secret object from storage
                obj_base= om_secrets.getBaseAddress(OM_TYPE, lock_id);
                if (obj_base==(short)0xFFFF){
                    resetLockThenThrow(SW_OBJECT_NOT_FOUND, false);
                }
                short obj_size= om_secrets.getSizeFromAddress(obj_base);

                // check export rights & update export_nb in object
                byte export_rights= (byte)(om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_CONTROL) & SECRET_EXPORT_MASK);
                if (lock_transport_mode== SECRET_EXPORT_ALLOWED){
                    if (export_rights!=SECRET_EXPORT_ALLOWED){
                        resetLockThenThrow(SW_EXPORT_NOT_ALLOWED, false);
                    }
                    byte counter = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBPLAIN);
                    counter++;
                    om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBPLAIN, counter);
                }
                else{
                    if (export_rights!=SECRET_EXPORT_ALLOWED && export_rights!=SECRET_EXPORT_SECUREONLY){
                        resetLockThenThrow(SW_EXPORT_NOT_ALLOWED, false);
                    }
                    byte counter = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE);
                    counter++;
                    om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE, counter);
                }
                
                // copy id & header to buffer
                Util.setShort(buffer, (short)0, lock_id);
                label_size= om_secrets.getObjectByte(obj_base, SECRET_OFFSET_LABEL_SIZE);
                om_secrets.getObjectData(obj_base, (short)0, buffer, (short)2, (short)(SECRET_HEADER_SIZE+label_size));
                lock_obj_offset= (short)(SECRET_HEADER_SIZE+label_size);
                lock_data_remaining= (short)(obj_size-lock_obj_offset);
                
                // initialize cipher & signature/hash for next phases
                om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
                
                if (lock_transport_mode== SECRET_EXPORT_ALLOWED){
                    sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
                    sigECDSA.update(buffer, (short)0, (short)(2+SECRET_HEADER_SIZE+label_size));
                    // buffer= [id(2b) | type(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | label_size(1b) | label]
                    return (short)(2+SECRET_HEADER_SIZE+label_size);
                }
                else{ 
                    // secure export
                    // save IV
                    Util.arrayCopyNonAtomic(secret_sc_buffer, OFFSET_SC_IV, buffer,(short)(2+SECRET_HEADER_SIZE+label_size), SIZE_SC_IV);
                    secret_sha256.reset();
                    //secret_sha256.update(buffer, (short)2, (short)(SECRET_HEADER_SIZE+label_size)); // hash all header data, including label
                    secret_sha256.update(buffer, (short)2, (short)(SECRET_HEADER_SIZE-1)); //do not hash label & label_size => may be changed during import
                    // buffer= [id(2b) | type(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | label_size(1b) | label | IV(16b)]
                    return (short)(2+SECRET_HEADER_SIZE+label_size+SIZE_SC_IV);
                } 
                
            case OP_PROCESS: // following requests
                // check lock
                if ( (lock_ins!= INS_EXPORT_SECRET) ||
                     (lock_lastop!= OP_INIT && lock_lastop != OP_PROCESS))
                {
                    resetLockThenThrow(SW_LOCK_ERROR, false);
                }

                // get secret from storage
                obj_base= om_secrets.getBaseAddress(OM_TYPE, lock_id);
                if (obj_base==(short)0xFFFF){
                    resetLockThenThrow(SW_OBJECT_NOT_FOUND, false);
                }

                // decrypt & export data chunk by chunk
                if (lock_data_remaining>CHUNK_SIZE){
                    //temporary copy chunk from object to recvBuffer and decrypt it
                    om_secrets.getObjectData(obj_base, lock_obj_offset, recvBuffer, (short)0, CHUNK_SIZE);
                    dec_size= om_aes128_ecb.update(recvBuffer, (short)0, CHUNK_SIZE, buffer, (short)2);
                    Util.setShort(buffer, (short)(0), dec_size);
                    
                    if (lock_transport_mode==SECRET_EXPORT_SECUREONLY){
                        // reencrypt with shared export key
                        enc_size= secret_sc_aes128_cbc.update(buffer, (short)2, CHUNK_SIZE, buffer, (short)2);
                        Util.setShort(buffer, (short)(0), enc_size);
                        // assert (enc_size == dec_size)
                        // hashing for mac
                        secret_sha256.update(buffer, (short) 2, enc_size);
                    }else{
                        // update sign with authentikey
                        sigECDSA.update(buffer, (short)2, dec_size);
                    }
                    
                    lock_obj_offset+= CHUNK_SIZE;
                    lock_data_remaining-=CHUNK_SIZE;
                    
                    // buffer= [data_size(2b) | data_chunk]
                    return (short)(2+dec_size);
                
                //finalize last chunk
                }else{ 
                    //temporary copy chunk from object to recvBuffer
                    om_secrets.getObjectData(obj_base, lock_obj_offset, recvBuffer, (short)0, lock_data_remaining);
                    // decrypt secret
                    dec_size= om_aes128_ecb.doFinal(recvBuffer, (short)0, lock_data_remaining, buffer, (short)2);
                    short sign_size=0;
                    if (lock_transport_mode==SECRET_EXPORT_SECUREONLY){
                        // finalize reencryption with shared key
                        dec_size= secret_sc_aes128_cbc.doFinal(buffer, (short)2, dec_size, buffer, (short)2);
                        Util.setShort(buffer, (short)(0), dec_size);
                        //todo: assert (dec_size==enc_size)
                        
                        // hash then hmac
                        sign_size=secret_sha256.doFinal(buffer, (short) 2, dec_size, buffer, (short)(2+dec_size+2) );
                        sign_size=HmacSha160.computeHmacSha160(secret_sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, (short)(2+dec_size+2), sign_size, buffer, (short)(2+dec_size+2) );
                        Util.setShort(buffer, (short)(2+dec_size), sign_size);
                    }
                    else{
                        //remove padding
                        byte padsize= buffer[(short)(2+dec_size-1)];
                        dec_size-=padsize;
                        Util.setShort(buffer, (short)(0), dec_size);
                        
                        // finalize sign with authentikey
                        sign_size= sigECDSA.sign(buffer, (short)2, dec_size, buffer, (short)(2+dec_size+2));
                        Util.setShort(buffer, (short)(2+dec_size), sign_size);
                    }
                    
                    lock_obj_offset+= lock_data_remaining;
                    lock_data_remaining=(short)0;
                                        
                    // log operation to be updated later
                    logger.updateLog(INS_EXPORT_SECRET, lock_id, lock_id_pubkey, (short)0x9000);
                    
                    // update/finalize lock
                    lock_enabled = false;
                    lock_ins= (byte)0x00;
                    lock_lastop= (byte)0x00;
                    lock_id=(short)-1;
                    lock_id_pubkey=(short)-1;
                    lock_transport_mode= (byte)0;
                    lock_obj_offset=(short)0;
                    
                    // the client can recover full public-key from the signature or
                    // by guessing the compression value () and verifying the signature... 
                    // buffer= [data_size(2b) | data_chunk | sigsize(2) | sig]
                    return (short)(2+dec_size+2+sign_size);                
                }
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
        }// end switch   
        
        return (short)(0); // should never happen
    }// end exportSecret

    /** 
     * This function exports a secret for secure import to a Satochip.
     * The secret is encrypted with a key is generated with ECDH, using the Satochip authentikey.
     * Compared to the exportSecret() method, this method is executed in one phase, and the secret size is reduced to the minimum (max 64b).
     * Only Masterseeds & 2FA secrets can be exported this way.
     * 
     * ins: 0xA8
     * p1: 0x00
     * p2: 0x00
     * data: [ id(2b) | id_pubkey(2b) ]
     * return: [ id(2b) | header(13b) | IV(16b) | encrypted_secret_size(2b) | encrypted_secret | hmac_size(2b) | hmac(20b) ]
     */
    private short exportSecretToSatochip(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = ISO7816.OFFSET_CDATA;
        short obj_base=(short)0;
        short dec_size=(short)0;
        short enc_size=(short)0;
        short label_size=(short)0;
                
        // log operation to be updated later
        logger.createLog(INS_EXPORT_SECRET, lock_id, lock_id_pubkey, (short)0x0000);

        // get id
        if (bytes_left<4){
            resetLockThenThrow(SW_INVALID_PARAMETER, false);
        }
        lock_id= Util.getShort(buffer, buffer_offset);
        buffer_offset+=2;
        lock_id_pubkey= Util.getShort(buffer, buffer_offset);
                    
        // PUBKEY OBJECT
        short base_pubkey= om_secrets.getBaseAddress(OM_TYPE, lock_id_pubkey);
        if (base_pubkey==(short)0xFFFF){
            resetLockThenThrow(SW_OBJECT_NOT_FOUND, false);
        }

        short obj_pubkey_size= om_secrets.getSizeFromAddress(base_pubkey);
        om_secrets.getObjectData(base_pubkey, (short)0, recvBuffer, (short)0, obj_pubkey_size);
        byte pubkey_type= recvBuffer[SECRET_OFFSET_TYPE];
        if  (pubkey_type!=SECRET_TYPE_PUBKEY){
            resetLockThenThrow(SW_WRONG_SECRET_TYPE, false);
        }
        // update export_pubkey_counter in object
        recvBuffer[SECRET_OFFSET_EXPORT_COUNTER]+=1;
        om_secrets.setObjectByte(base_pubkey, SECRET_OFFSET_EXPORT_COUNTER, recvBuffer[SECRET_OFFSET_EXPORT_COUNTER]);
                    
        // get pubkey data 
        label_size= recvBuffer[SECRET_OFFSET_LABEL_SIZE];
        short data_offset= (short) (SECRET_HEADER_SIZE + label_size);
        // initialize cipher for pubkey decryption
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
        dec_size= om_aes128_ecb.doFinal(recvBuffer, data_offset, (short)80, recvBuffer, data_offset); //size should be 65+1+padding
        short pubkey_size= recvBuffer[data_offset];
        if (pubkey_size != 65){
            resetLockThenThrow(SW_INVALID_PARAMETER, false);
        }

        // compute shared static key 
        keyAgreement.init(authentikey_private);        
        keyAgreement.generateSecret(recvBuffer, (short)(data_offset+1), (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form
        // derive secret_sessionkey & secret_mackey
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, SECRET_CST_SC, (short)6, (short)6, recvBuffer, (short)33);
        Util.arrayCopyNonAtomic(recvBuffer, (short)33, secret_sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, SECRET_CST_SC, (short)0, (short)6, recvBuffer, (short)33);
        secret_sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!   
        randomData.generateData(secret_sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
        secret_sc_aes128_cbc.init(secret_sc_sessionkey, Cipher.MODE_ENCRYPT, secret_sc_buffer, OFFSET_SC_IV, SIZE_SC_IV);
        
        // SECRET OBJECT
        // get secret object from storage
        obj_base= om_secrets.getBaseAddress(OM_TYPE, lock_id);
        if (obj_base==(short)0xFFFF){
            resetLockThenThrow(SW_OBJECT_NOT_FOUND, false);
        }
        short obj_size= om_secrets.getSizeFromAddress(obj_base);
        
        //check type if export to satochip
        byte obj_type = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_TYPE);
        if (obj_type != SECRET_TYPE_MASTER_SEED && obj_type != SECRET_TYPE_2FA){
            resetLockThenThrow(SW_WRONG_SECRET_TYPE, false);
        }

        // check object export rights & update export_nb in object
        byte export_rights= (byte)(om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_CONTROL) & SECRET_EXPORT_MASK);
        if (export_rights!=SECRET_EXPORT_ALLOWED && export_rights!=SECRET_EXPORT_SECUREONLY){
            resetLockThenThrow(SW_EXPORT_NOT_ALLOWED, false);
        }
        byte counter = om_secrets.getObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE);
        counter++;
        om_secrets.setObjectByte(obj_base, SECRET_OFFSET_EXPORT_NBSECURE, counter);

        // reset buffer_offset to write output
        buffer_offset= 0;

        // copy id & header (without label) to buffer
        Util.setShort(buffer, buffer_offset, lock_id);
        buffer_offset+=2;
        label_size= om_secrets.getObjectByte(obj_base, SECRET_OFFSET_LABEL_SIZE);
        om_secrets.getObjectData(obj_base, (short)0, buffer, buffer_offset, SECRET_HEADER_SIZE); // header without label
        buffer[(short)(buffer_offset+SECRET_OFFSET_LABEL_SIZE)]= (byte)0; // set label_size to 0
        buffer[(short)(buffer_offset+SECRET_OFFSET_SUBTYPE)]= (byte)0; // reset subtype to 0 (default: Masterseed without any meta data)
        buffer_offset+=SECRET_HEADER_SIZE;
        lock_obj_offset= (short)(SECRET_HEADER_SIZE+label_size);
        lock_data_remaining= (short)(obj_size-lock_obj_offset);

        // save IV
        Util.arrayCopyNonAtomic(secret_sc_buffer, OFFSET_SC_IV, buffer, buffer_offset, SIZE_SC_IV);
        buffer_offset+=SIZE_SC_IV;
        buffer_offset+=2; // skip 2 bytes (dec_size) for later
                    
        // in case of masterseed with BIP39v2 data, we only need to export the masterseed to limit size footprint
        //temporary copy first chunk of data from object to recvBuffer
        if (lock_data_remaining>CHUNK_SIZE)
            lock_data_remaining= CHUNK_SIZE;
        om_secrets.getObjectData(obj_base, lock_obj_offset, recvBuffer, (short)0, lock_data_remaining);
        // initialize cipher & decrypt secret
        om_aes128_ecb.init(om_encryptkey, Cipher.MODE_DECRYPT);
        dec_size= om_aes128_ecb.update(recvBuffer, (short)0, lock_data_remaining, buffer, buffer_offset);
                    
        // in case of masterseed with BIP39v2 data, we only need to export the masterseed to limit size footprint
        short secret_size = buffer[buffer_offset];
        if (secret_size>64){
            resetLockThenThrow(SW_WRONG_SECRET_TYPE, false);
        }
        secret_size++; // secret_size now includes the size byte
                    
        // recompute & update fingerprint
        secret_sha256.reset();
        secret_sha256.doFinal(buffer, buffer_offset, secret_size, recvBuffer, (short)(0) );
        Util.arrayCopyNonAtomic(recvBuffer, (short)0, buffer, (short)(2+SECRET_OFFSET_FINGERPRINT), (short)4);

        // redo padding with updated secret
        short pad_size = (short)(AES_BLOCKSIZE - (secret_size%AES_BLOCKSIZE));
        Util.arrayFillNonAtomic(buffer, (short)(buffer_offset+secret_size), pad_size, (byte)pad_size);
        // reencrypt new data with shared export key
        dec_size= secret_sc_aes128_cbc.doFinal(buffer, buffer_offset, (short)(secret_size+pad_size), buffer, buffer_offset);
        Util.setShort(buffer, (short)(buffer_offset-2), dec_size);

        // hash then hmac
        secret_sha256.reset();
        // hash header (without label_size & label)
        secret_sha256.update(buffer, (short)2, (short)(SECRET_HEADER_SIZE-1)); //do not hash label & label_size => may be changed during import
        //secret_sha256.update(buffer, (short)2, (short)(SECRET_HEADER_SIZE+label_size)); // hash all header data, including label
        // hash encrypted secret
        short sign_size=secret_sha256.doFinal(buffer, buffer_offset, dec_size, buffer, (short)(buffer_offset+dec_size+2) );
        sign_size=HmacSha160.computeHmacSha160(secret_sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, (short)(buffer_offset+dec_size+2), sign_size, buffer, (short)(buffer_offset+dec_size+2) );
        Util.setShort(buffer, (short)(buffer_offset+dec_size), sign_size);

        // log operation to be updated later
        logger.updateLog(INS_EXPORT_SECRET_TO_SATOCHIP, lock_id, lock_id_pubkey, (short)0x9000);
        
        // buffer= [id(2b) | header(13b)| IV(16b) | encrypted_secret_size(2b) | encrypted_secret | hmacsize(2) | hmac]
        return (short)(buffer_offset+2+dec_size+2+sign_size);

    }// end exportSecretToSatochip

    /** 
     * This function list all the objects stored in secure memory
     * Only the header data of each object is returned.
     * The sensitive data (which is encrypted) is not returned.
     * This function must be initially called with the INIT option. 
     * The function only returns one object information at a time and must be
     * called in repetition until SW_SUCCESS is returned with no further data.
     * Applications cannot rely on any special ordering of the sequence of returned objects. 
     * 
     * ins: 0xA6
     * p1: 0x00 
     * p2: OP_INIT (reset and get first entry) or OP_PROCESS (next entry)
     * data: (none)
     * return: [object_id(2b) | type(1b) | export_control(1b) | nb_export_plain(1b) | nb_export_secure(1b) | label_size(1b) | label ]
     */
    private short listSecretHeaders(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short base=(short)0;
        short labelsize=(short)0;
        if (buffer[ISO7816.OFFSET_P2] == OP_INIT){
            base = om_secrets.getFirstRecord();
        }
        else if (buffer[ISO7816.OFFSET_P2] == OP_PROCESS){
            base = om_secrets.getNextRecord();
        }
        else{
            ISOException.throwIt(SW_INCORRECT_P2);
        }
        if (base==(short)0xFFFF)
            ISOException.throwIt(SW_SEQUENCE_END);
        
        short id= om_secrets.getIdFromAddress(base);
        Util.setShort(buffer, (short)0, id);
        labelsize= Util.makeShort((byte)0, om_secrets.getObjectByte(base,SECRET_OFFSET_LABEL_SIZE));
        om_secrets.getObjectData(base, (short)0, buffer, (short)2, (short)(SECRET_HEADER_SIZE+labelsize));
        
        //TODO: sign with authentikey 
        return (short)(2+SECRET_HEADER_SIZE+labelsize);
    }

    /** 
     * This function reset a secret object in memory.
     * TODO: evaluate security implications!
     * 
     * ins: 0xA5
     * p1: 0
     * p2: 0
     * data: [ id(2b) ]
     * return: (none)
     * throws: SW_OBJECT_NOT_FOUND if no object with given sid found
     */
    private short resetSecret(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        // log operation
        logger.createLog(INS_RESET_SECRET, (short)-1, (short)-1, (short)0x0000);

        // get id from buffer
        short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytes_left<2){
            ISOException.throwIt(SW_INVALID_PARAMETER);
        }
        short id = Util.getShort(buffer, ISO7816.OFFSET_CDATA);

        //find and delete object, zeroize memory by default!
        boolean isReset = om_secrets.destroyObject(OM_TYPE, id, true);

        if (!isReset){
            // update log operation fail
            logger.updateLog(INS_RESET_SECRET, id, (short)-1, SW_OBJECT_NOT_FOUND);
            ISOException.throwIt(SW_OBJECT_NOT_FOUND);
        } else {
            // update log operation success
            logger.updateLog(INS_RESET_SECRET, id, (short)-1, ISO7816.SW_NO_ERROR);
        }

        return (short)0;
    }// end resetSecret

    /** 
     * This function returns the logs stored in the card
     * 
     * This function must be initially called with the INIT option. 
     * The function only returns one object information at a time and must be
     * called in repetition until SW_SUCCESS is returned with no further data.
     * Log are returned starting with the most recent log first. 
     * 
     * ins: 0xA9
     * p1: 0x00 
     * p2: OP_INIT (reset and get first entry) or OP_PROCESS (next entry)
     * data: (none)
     * return: 
     *      OP_INIT: [nbtotal_logs(2b) | nbavail_logs(2b)]
     *      OP_PROCESS: [logs(7b)]
     */
    private short printLogs(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short buffer_offset=(short)0;
        if (buffer[ISO7816.OFFSET_P2] == OP_INIT){
            boolean is_log= logger.getFirstRecord(buffer, buffer_offset);
            if (is_log)
                return (short)(4+Logger.LOG_SIZE);
            else
                return (short)4;        
        }
        else if (buffer[ISO7816.OFFSET_P2] == OP_PROCESS){
            while(logger.getNextRecord(buffer, buffer_offset)){
                buffer_offset+=Logger.LOG_SIZE;
                if (buffer_offset>=128)
                    break;
            }
            return buffer_offset;
        }
        else{
            ISOException.throwIt(SW_INCORRECT_P2);
        }
        return buffer_offset;
    }
    
    /** 
     * DEPRECATED
     * This function creates a PIN with parameters specified by the P1, P2 and DATA
     * values. P2 specifies the maximum number of consecutive unsuccessful
     * verifications before the PIN blocks. PIN can be created only if one of the logged identities
     * allows it. 
     * 
     * ins: 0x40
     * p1: PIN number (0x00-0x07)
     * p2: max attempt number
     * data: [PIN_size(1b) | PIN | UBLK_size(1b) | UBLK] 
     * return: none
     */
    // private short CreatePIN(APDU apdu, byte[] buffer) {
    //     // check that PIN[0] has been entered previously
    //     if (!pin.isValidated())
    //         ISOException.throwIt(SW_UNAUTHORIZED);

    //     byte pin_nb = buffer[ISO7816.OFFSET_P1];
    //     byte num_tries = buffer[ISO7816.OFFSET_P2];

    //     if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS) || (pins[pin_nb] != null))
    //         ISOException.throwIt(SW_INCORRECT_P1);
    //     /* Allow pin lengths > 127 (useful at all ?) */
    //     short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
    //     // At least 1 character for PIN and 1 for unblock code (+ lengths)
    //     if (bytesLeft < 4)
    //         ISOException.throwIt(SW_INVALID_PARAMETER);
    //     byte pin_size = buffer[ISO7816.OFFSET_CDATA];
    //     if (bytesLeft < (short) (1 + pin_size + 1))
    //         ISOException.throwIt(SW_INVALID_PARAMETER);
    //     if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
    //         ISOException.throwIt(SW_INVALID_PARAMETER);
    //     byte ucode_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
    //     if (bytesLeft != (short) (1 + pin_size + 1 + ucode_size))
    //         ISOException.throwIt(SW_INVALID_PARAMETER);
    //     if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), ucode_size))
    //         ISOException.throwIt(SW_INVALID_PARAMETER);
    //     pins[pin_nb] = new OwnerPIN(num_tries, PIN_MAX_SIZE);
    //     pins[pin_nb].update(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size);
    //     ublk_pins[pin_nb] = new OwnerPIN((byte) 3, PIN_MAX_SIZE);
    //     // Recycle variable pin_size
    //     pin_size = (byte) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1);
    //     ublk_pins[pin_nb].update(buffer, pin_size, ucode_size);

    //     return (short)0;
    // }

    /** 
     * This function verifies a PIN number sent by the DATA portion. The length of
     * this PIN is specified by the value contained in P3.
     * Multiple consecutive unsuccessful PIN verifications will block the PIN. If a PIN
     * blocks, then an UnblockPIN command can be issued.
     * 
     * ins: 0x42
     * p1: 0x00 (PIN number)
     * p2: 0x00
     * data: [PIN] 
     * return: none (throws an exception in case of wrong PIN)
     */
    private short VerifyPIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        // if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
        //     ISOException.throwIt(SW_INCORRECT_P1);
        if (pin_nb != 0)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);

        //OwnerPIN pin = pins[pin_nb];
        if (pin == null)
            return (short)0; //verifyPIN does not fail if no PIN (i.e. before setup)
            //ISOException.throwIt(SW_INCORRECT_P1);
        

        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        /*
         * Here I suppose the PIN code is small enough to enter in the buffer
         * TODO: Verify the assumption and eventually adjust code to support
         * reading PIN in multiple read()s
         */
        if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) bytesLeft))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) bytesLeft)) {
            logger.createLog(INS_VERIFY_PIN, (short)-1, (short)-1, (short)(SW_PIN_FAILED + triesRemaining - 1) );
            ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));
        }

        return (short)0;
    }

    /** 
     * This function changes a PIN code. The DATA portion contains both the old and
     * the new PIN codes. 
     * 
     * ins: 0x44
     * p1: 0x00 (PIN number)
     * p2: 0x00
     * data: [PIN_size(1b) | old_PIN | PIN_size(1b) | new_PIN ] 
     * return: none (throws an exception in case of wrong PIN)
     */
    private short ChangePIN(APDU apdu, byte[] buffer) {
        /*
         * Here I suppose the PIN code is small enough that 2 of them enter in
         * the buffer TODO: Verify the assumption and eventually adjust code to
         * support reading PINs in multiple read()s
         */
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        // if ((pin_nb < 0) || (pin_nb >= MAX_NUM_PINS))
        //     ISOException.throwIt(SW_INCORRECT_P1);
        if (pin_nb != 0)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        // At least 1 character for each PIN code
        if (bytesLeft < 4)
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte pin_size = buffer[ISO7816.OFFSET_CDATA];
        if (bytesLeft < (short) (1 + pin_size + 1))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte new_pin_size = buffer[(short) (ISO7816.OFFSET_CDATA + 1 + pin_size)];
        if (bytesLeft < (short) (1 + pin_size + 1 + new_pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        if (!CheckPINPolicy(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size))
            ISOException.throwIt(SW_INVALID_PARAMETER);

        byte triesRemaining = pin.getTriesRemaining();
        if (triesRemaining == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!pin.check(buffer, (short) (ISO7816.OFFSET_CDATA + 1), pin_size)) {
            logger.createLog(INS_CHANGE_PIN, (short)-1, (short)-1, (short)(SW_PIN_FAILED + triesRemaining - 1) );
            ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));
        }

        pin.update(buffer, (short) (ISO7816.OFFSET_CDATA + 1 + pin_size + 1), new_pin_size);

        return (short)0;
    }

    /**
     * This function unblocks a PIN number using the unblock code specified in the
     * DATA portion. The P3 byte specifies the unblock code length. 
     * If the PIN is blocked and the PUK is blocked, proceed to reset to factory.
     * 
     * ins: 0x46
     * p1: 0x00 (PUK number)
     * p2: 0x00
     * data: [PUK] 
     * return: none (throws an exception in case of wrong PUK)
     */
    private short UnblockPIN(APDU apdu, byte[] buffer) {
        byte pin_nb = buffer[ISO7816.OFFSET_P1];
        if (pin_nb  != 0)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);
        
        // OwnerPIN pin = pins[pin_nb];
        // OwnerPIN ublk_pin = ublk_pins[pin_nb];
        if (pin == null)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (ublk_pin == null)
            ISOException.throwIt(SW_INTERNAL_ERROR);
        // If the PIN is not blocked, the call is inconsistent
        if (pin.getTriesRemaining() != 0)
            ISOException.throwIt(SW_OPERATION_NOT_ALLOWED);
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        /*
         * Here I suppose the PIN code is small enough to fit into the buffer
         * TODO: Verify the assumption and eventually adjust code to support
         * reading PIN in multiple read()s
         */
        if (!CheckPINPolicy(buffer, ISO7816.OFFSET_CDATA, (byte) bytesLeft))
            ISOException.throwIt(SW_INVALID_PARAMETER);
        byte triesRemaining = ublk_pin.getTriesRemaining();
        if (triesRemaining == (byte) 0x00)
            ISOException.throwIt(SW_IDENTITY_BLOCKED);
        if (!ublk_pin.check(buffer, ISO7816.OFFSET_CDATA, (byte) bytesLeft)){
            logger.createLog(INS_UNBLOCK_PIN, (short)-1, (short)-1, (short)(SW_PIN_FAILED + triesRemaining - 1) );
            // if PUK is blocked, proceed to factory reset
            if (ublk_pin.getTriesRemaining() == (byte) 0x00){
                resetToFactory();
                ISOException.throwIt(SW_RESET_TO_FACTORY);
            }
            ISOException.throwIt((short)(SW_PIN_FAILED + triesRemaining - 1));
        }

        pin.resetAndUnblock();

        return (short)0;
    }

    private short LogOutAll() {
        if (pin != null)
            pin.reset();
        return (short)0;
    }

    /**
     * DEPRECATED
     * This function returns a 2 byte bit mask of the available PINs that are currently in
     * use. Each set bit corresponds to an active PIN.
     * 
     *  ins: 0x48
     *  p1: 0x00
     *  p2: 0x00
     *  data: none
     *  return: [RFU(1b) | PIN_mask(1b)]
     */
    // private short ListPINs(APDU apdu, byte[] buffer) {
    //     // check that PIN[0] has been entered previously
    //     if (!pin.isValidated())
    //         ISOException.throwIt(SW_UNAUTHORIZED);

    //     // Checking P1 & P2
    //     if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
    //         ISOException.throwIt(SW_INCORRECT_P1);
    //     if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
    //         ISOException.throwIt(SW_INCORRECT_P2);
    //     byte expectedBytes = buffer[ISO7816.OFFSET_LC];
    //     if (expectedBytes != (short) 2)
    //         ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    //     // Build the PIN bit mask
    //     short mask = (short) 0x00;
    //     short b;
    //     for (b = (short) 0; b < MAX_NUM_PINS; b++)
    //         if (pins[b] != null)
    //             mask |= (short) (((short) 0x01) << b);
    //     // Fill the buffer
    //     Util.setShort(buffer, (short) 0, mask);
    //     // Send response
    //     return (short)2;
    // }

    /**
     * This function retrieves general information about the Applet running on the smart
     * card, and useful information about the status of current session such as:
     *      - applet version (4b)
     *  
     *  ins: 0x3C
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [versions(4b) | PIN0-PUK0-PIN1-PUK1 tries (4b) | needs2FA (1b) | is_seeded(1b) | setupDone(1b) | needs_secure_channel(1b) | nfc_policy(1b)]
     */
    private short GetStatus(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        //if (!pin.isValidated())
        // ISOException.throwIt(SW_UNAUTHORIZED);

        if (buffer[ISO7816.OFFSET_P1] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P1);
        if (buffer[ISO7816.OFFSET_P2] != (byte) 0x00)
            ISOException.throwIt(SW_INCORRECT_P2);

        // applet version
        short pos = (short) 0;
        buffer[pos++] = PROTOCOL_MAJOR_VERSION; // Major Card Edge Protocol version n.
        buffer[pos++] = PROTOCOL_MINOR_VERSION; // Minor Card Edge Protocol version n.
        buffer[pos++] = APPLET_MAJOR_VERSION; // Major Applet version n.
        buffer[pos++] = APPLET_MINOR_VERSION; // Minor Applet version n.
        // PIN/PUK remaining tries available
        if (setupDone){
            buffer[pos++] = pin.getTriesRemaining();
            buffer[pos++] = ublk_pin.getTriesRemaining();
            buffer[pos++] = (byte) 0; //pins[1].getTriesRemaining();
            buffer[pos++] = (byte) 0; //ublk_pins[1].getTriesRemaining();
        } else {
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
            buffer[pos++] = (byte) 0;
        }
        // 2FA status
        if (false) //  maintained for intercompatibility with Satochip but not (currently) used in seedkeeper
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // bip32_seeded
        if (true) // maintained for intercompatibility with Satochip but not used in seedkeeper
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // setup status
        if (setupDone)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // secure channel support
        if (needs_secure_channel)
            buffer[pos++] = (byte)0x01;
        else
            buffer[pos++] = (byte)0x00;
        // NFC policy
        buffer[pos++] = nfc_policy;

        return pos;
    }

    /**
     * This function retrieves information specific about the SeedKeeper applet running on the smart
     * card, and useful information about the status of current session such as:
     *      - number of secrets (objects) stored in the card
     *      - total memory available
     *      - free memory available
     *      - total number of events logged
     *      - number of logs available (older logs are overwritten)
     *      - last event logged
     * 
     *  ins: 0xA7
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [nb_objects(2b) | total_memory(2b) | free_mem(2b) | nb_total_logs(2b) | nb_avail_logs(2b) | last_log(7)]
     */
    private short GetSeedKeeperStatus(APDU apdu, byte[] buffer) {
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);

        short buffer_offset = (short) 0;
        // memory status
        Util.setShort(buffer, buffer_offset, om_secrets.getObjectNumber());
        buffer_offset+=(short)2;
        Util.setShort(buffer, buffer_offset, om_secrets.totalmem());
        buffer_offset+=(short)2;
        Util.setShort(buffer, buffer_offset, om_secrets.freemem());
        buffer_offset+=(short)2;


        // logging status [nb_total_logs(2b) | nb_avail_logs(2b) | last_log(7b)]
        boolean is_log= logger.getFirstRecord(buffer, buffer_offset);
        if (!is_log){
            // empty log
            Util.arrayFillNonAtomic(buffer, (short)(buffer_offset+4), Logger.LOG_SIZE, (byte)0);
        }
        buffer_offset+= (short)(4+Logger.LOG_SIZE);

        return buffer_offset;
    }

    /**
     * This function allows to define or recover a short description of the card.
     * 
     *  ins: 0x3D
     *  p1: 0x00 
     *  p2: operation (0x00 to set label, 0x01 to get label)
     *  data: [label_size(1b) | label ] if p2==0x00 else (none)
     *  return: [label_size(1b) | label ] if p2==0x01 else (none)
     */
    private short card_label(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch (op) {
            case 0x00: // set label
                short bytes_left = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                short buffer_offset = ISO7816.OFFSET_CDATA;
                if (bytes_left>0){
                    short label_size= Util.makeShort((byte) 0x00, buffer[buffer_offset]);
                    if (label_size>bytes_left)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    if (label_size>MAX_CARD_LABEL_SIZE)
                        ISOException.throwIt(SW_INVALID_PARAMETER);
                    card_label_size= buffer[buffer_offset];
                    bytes_left--;
                    buffer_offset++;
                    Util.arrayCopyNonAtomic(buffer, buffer_offset, card_label, (short)0, label_size);
                }
                else if (bytes_left==0){//reset label
                    card_label_size= (byte)0x00;
                }
                return (short)0;
                
            case 0x01: // get label
                buffer[(short)0]=card_label_size;
                Util.arrayCopyNonAtomic(card_label, (short)0, buffer, (short)1, card_label_size);
                return (short)(card_label_size+1);
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
                
        }//end switch()
        
        return (short)0;
    }

    /**
     * This function enables of disables the NFC interface.
     * By default, NFC interface is enabled. 
     * NFC access can only be changed through the contact interface.
     * PIN must be validated to use this function.
     * NFC access policy is defined with 1 byte:
     *  - NFC_ENABLED: NFC enabled
     *  - NFC_DISABLED: NFC disabled but can be reenabled
     *  - NFC_BLOCKED: NFC disabled and can only be reenable by factory reset!
     * 
     * 
     *  ins: 0x3E
     *  p1: NFC access policy
     *  p2: RFU (set specific permission policies for NFC interface)
     *  data: (none)
     *  return: (none)
     */
    private short setNfcPolicy(APDU apdu, byte[] buffer){
        // check that PIN has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);


        // check that the contact interface is used
        byte protocol = (byte) (APDU.getProtocol() & APDU.PROTOCOL_MEDIA_MASK);
        if (protocol != APDU.PROTOCOL_MEDIA_USB && protocol != APDU.PROTOCOL_MEDIA_DEFAULT) {
            ISOException.throwIt(SW_NFC_DISABLED);
        }

        // check if status change is allowed
        // if NFC is blocked, it is not allowed to unblock it, except via factory reset!
        if (nfc_policy == NFC_BLOCKED)
            ISOException.throwIt(SW_NFC_BLOCKED);

        // get new NFC status from P1
        byte nfc_policy_new = buffer[ISO7816.OFFSET_P1];
        if (nfc_policy_new<0 || nfc_policy_new>2)
            ISOException.throwIt(SW_INCORRECT_P1);

        // update NFC access policy
        nfc_policy = nfc_policy_new;

        return (short)0;
    }

    /**
     * DEPRECATED - use exportAuthentikey() instead
     * This function returns the authentikey public key (uniquely derived from the Bip32 seed).
     * The function returns the x-coordinate of the authentikey, self-signed.
     * The authentikey full public key can be recovered from the signature.
     * 
     *  ins: 0x73
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
     */
    private short getBIP32AuthentiKey(APDU apdu, byte[] buffer){
        return getAuthentikey(apdu, buffer);
    }
    
    /**
     * This function returns the authentikey public key.
     * The function returns the x-coordinate of the authentikey, self-signed.
     * The authentikey full public key can be recovered from the signature.
     * 
     * Compared to getBIP32AuthentiKey(), this method returns the Authentikey even if the card is not seeded.
     * For SeedKeeper encrypted seed import, we use the authentikey as a Trusted Pubkey for the ECDH key exchange, 
     * thus the authentikey must be available before the Satochip is seeded. 
     * Before a seed is available, the authentiey is generated oncard randomly in the constructor
     * 
     *  ins: 0xAD
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: none
     *  return: [coordx_size(2b) | coordx | sig_size(2b) | sig]
     */
    private short getAuthentikey(APDU apdu, byte[] buffer){
        // check that PIN[0] has been entered previously
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        // get the partial authentikey public key...
        authentikey_public.getW(buffer, (short)1);
        Util.setShort(buffer, (short)0, BIP32_KEY_SIZE);
        // self signed public key
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+2), buffer, (short)(BIP32_KEY_SIZE+4));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+2), sign_size);
        
        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig]
        return (short)(BIP32_KEY_SIZE+sign_size+4);
    }
    
    /**
     * This function allows to initiate a Secure Channel
     *  
     *  ins: 0x81
     *  p1: 0x00
     *  p2: 0x00
     *  data: [client-pubkey(65b)]
     *  return: [coordx_size(2b) | authentikey-coordx | sig_size(2b) | self-sig | sig2_size(optional) | authentikey-sig(optional)]
     */
    private short InitiateSecureChannel(APDU apdu, byte[] buffer){

        // get client pubkey
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)65)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        if (buffer[ISO7816.OFFSET_CDATA] != (byte)0x04)
            ISOException.throwIt(SW_INVALID_PARAMETER);

        // generate a new ephemeral key
        sc_ephemeralkey.clearKey(); //todo: simply generate new random S param instead?
        Secp256k1.setCommonCurveParameters(sc_ephemeralkey);// keep public params!
        randomData.generateData(recvBuffer, (short)0, BIP32_KEY_SIZE);
        sc_ephemeralkey.setS(recvBuffer, (short)0, BIP32_KEY_SIZE); //random value first

        // compute the shared secret...
        keyAgreement.init(sc_ephemeralkey);        
        keyAgreement.generateSecret(buffer, ISO7816.OFFSET_CDATA, (short) 65, recvBuffer, (short)0); //pubkey in uncompressed form
        // derive sc_sessionkey & sc_mackey
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, CST_SC, (short)6, (short)6, recvBuffer, (short)33);
        Util.arrayCopyNonAtomic(recvBuffer, (short)33, sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY);
        HmacSha160.computeHmacSha160(recvBuffer, (short)1, (short)32, CST_SC, (short)0, (short)6, recvBuffer, (short)33);
        sc_sessionkey.setKey(recvBuffer,(short)33); // AES-128: 16-bytes key!!       

        //reset IV counter
        Util.arrayFillNonAtomic(sc_buffer, OFFSET_SC_IV, SIZE_SC_IV, (byte) 0);

        // self signed ephemeral pubkey
        keyAgreement.generateSecret(Secp256k1.SECP256K1, Secp256k1.OFFSET_SECP256K1_G, (short) 65, buffer, (short)1); //pubkey in uncompressed form
        Util.setShort(buffer, (short)0, BIP32_KEY_SIZE);
        sigECDSA.init(sc_ephemeralkey, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(buffer, (short)0, (short)(BIP32_KEY_SIZE+2), buffer, (short)(BIP32_KEY_SIZE+4));
        Util.setShort(buffer, (short)(BIP32_KEY_SIZE+2), sign_size);

        // hash signed by authentikey
        short offset= (short)(2+BIP32_KEY_SIZE+2+sign_size);
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign2_size= sigECDSA.sign(buffer, (short)0, offset, buffer, (short)(offset+2));
        Util.setShort(buffer, offset, sign2_size);
        offset+=(short)(2+sign2_size); 

        initialized_secure_channel= true;

        // return x-coordinate of public key+signature
        // the client can recover full public-key from the signature or
        // by guessing the compression value () and verifying the signature... 
        // buffer= [coordx_size(2) | coordx | sigsize(2) | sig | sig2_size(optional) | sig2(optional)]
        return offset;
    }

    /**
     * This function allows to decrypt a secure channel message
     *  
     *  ins: 0x82
     *  
     *  p1: 0x00 (RFU)
     *  p2: 0x00 (RFU)
     *  data: [IV(16b) | data_size(2b) | encrypted_command | mac_size(2b) | mac]
     *  
     *  return: [decrypted command]
     *   
     */
    private short ProcessSecureChannel(APDU apdu, byte[] buffer){

        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short offset = ISO7816.OFFSET_CDATA;

        if (!initialized_secure_channel){
            ISOException.throwIt(SW_SECURE_CHANNEL_UNINITIALIZED);
        }

        // check hmac
        if (bytesLeft<18)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizein = Util.getShort(buffer, (short) (offset+SIZE_SC_IV));
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizemac= Util.getShort(buffer, (short) (offset+SIZE_SC_IV+2+sizein));
        if (sizemac != (short)20)
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);
        if (bytesLeft<(short)(SIZE_SC_IV+2+sizein+2+sizemac))
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        HmacSha160.computeHmacSha160(sc_buffer, OFFSET_SC_MACKEY, SIZE_SC_MACKEY, buffer, offset, (short)(SIZE_SC_IV+2+sizein), tmpBuffer2, (short)0);
        if ( Util.arrayCompare(tmpBuffer2, (short)0, buffer, (short)(offset+SIZE_SC_IV+2+sizein+2), (short)20) != (byte)0 )
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_MAC);

        // process IV
        // IV received from client should be odd and strictly greater than locally saved IV
        // IV should be random (the 12 first bytes), never reused (the last 4 bytes counter) and different for send and receive
        if ((buffer[(short)(offset+SIZE_SC_IV-(short)1)] & (byte)0x01)==0x00)// should be odd
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        if ( !Biginteger.lessThan(sc_buffer, OFFSET_SC_IV_COUNTER, buffer, (short)(offset+SIZE_SC_IV_RANDOM), SIZE_SC_IV_COUNTER ) ) //and greater than local IV
            ISOException.throwIt(SW_SECURE_CHANNEL_WRONG_IV);
        // update local IV
        Util.arrayCopy(buffer, (short)(offset+SIZE_SC_IV_RANDOM), sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        Biginteger.add1_carry(sc_buffer, OFFSET_SC_IV_COUNTER, SIZE_SC_IV_COUNTER);
        randomData.generateData(sc_buffer, OFFSET_SC_IV_RANDOM, SIZE_SC_IV_RANDOM);
        sc_aes128_cbc.init(sc_sessionkey, Cipher.MODE_DECRYPT, buffer, offset, SIZE_SC_IV);
        offset+=SIZE_SC_IV;
        bytesLeft-=SIZE_SC_IV;

        //decrypt command
        offset+=2;
        bytesLeft-=2;
        if (bytesLeft<sizein)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        short sizeout=sc_aes128_cbc.doFinal(buffer, offset, sizein, buffer, (short) (0));
        return sizeout;
    }
    
    
    /*********************************************
     *      Methods for PKI personalization      *
     *********************************************/
    
    /**
     * This function is used to self-sign the CSR of the device
     *  
     *  ins: 0x94
     *  p1: 0x00  
     *  p2: 0x00 
     *  data: [hash(32b)]
     *  return: [signature]
     */
    private short sign_PKI_CSR(APDU apdu, byte[] buffer) {
        if (personalizationDone)
            ISOException.throwIt(SW_PKI_ALREADY_LOCKED);
        
        // check that PIN[0] has been entered previously
        if (pin != null && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);        
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.signPreComputedHash(buffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, buffer, (short)0);
        return sign_size;
    }
    
    /**
     * This function export the ECDSA secp256k1 public key that corresponds to the private key
     *  
     *  ins: 
     *  p1: 0x00
     *  p2: 0x00 
     *  data: [none]
     *  return: [ pubkey (65b) ]
     */
    private short export_PKI_pubkey(APDU apdu, byte[] buffer) {
        // check that PIN[0] has been entered previously
        if (pin != null  && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        authentikey_public.getW(buffer, (short)0); 
        return (short)65;
    }
    
    /**
     * This function imports the device certificate
     *  
     *  ins: 
     *  p1: 0x00
     *  p2: Init-Update 
     *  data(init): [ full_size(2b) ]
     *  data(update): [chunk_offset(2b) | chunk_size(2b) | chunk_data ]
     *  return: [none]
     */
    private short import_PKI_certificate(APDU apdu, byte[] buffer) {
        if (personalizationDone)
            ISOException.throwIt(SW_PKI_ALREADY_LOCKED);
        
        // check that PIN[0] has been entered previously
        if (pin != null && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        short buffer_offset = (short) (ISO7816.OFFSET_CDATA);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch(op){
            case OP_INIT:
                if (bytesLeft < (short)2)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                short new_certificate_size=Util.getShort(buffer, buffer_offset);
                if (new_certificate_size < 0)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (authentikey_certificate==null){
                    // create array
                    authentikey_certificate= new byte[new_certificate_size];
                    authentikey_certificate_size=new_certificate_size;
                }else{
                    if (new_certificate_size>authentikey_certificate.length)
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    authentikey_certificate_size=new_certificate_size;
                }
                break;
                
            case OP_PROCESS: 
                if (bytesLeft < (short)4)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                short chunk_offset= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                short chunk_size= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                bytesLeft-=4;
                if (bytesLeft < chunk_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if ((chunk_offset<0) || (chunk_offset>=authentikey_certificate_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (((short)(chunk_offset+chunk_size))>authentikey_certificate_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                Util.arrayCopyNonAtomic(buffer, buffer_offset, authentikey_certificate, chunk_offset, chunk_size);
                break;
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
        }
        return (short)0;
    }
    
    /**
     * This function exports the device certificate
     *  
     *  ins: 
     *  p1: 0x00  
     *  p2: Init-Update 
     *  data(init): [ none ]
     *  return(init): [ full_size(2b) ]
     *  data(update): [ chunk_offset(2b) | chunk_size(2b) ]
     *  return(update): [ chunk_data ] 
     */
    private short export_PKI_certificate(APDU apdu, byte[] buffer) {
        // check that PIN[0] has been entered previously
        if (pin != null && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        byte op = buffer[ISO7816.OFFSET_P2];
        switch(op){
            case OP_INIT:
                Util.setShort(buffer, (short)0, authentikey_certificate_size);
                return (short)2; 
                
            case OP_PROCESS: 
                short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
                if (bytesLeft < (short)4)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                
                short buffer_offset = (short) (ISO7816.OFFSET_CDATA);
                short chunk_offset= Util.getShort(buffer, buffer_offset);
                buffer_offset+=2;
                short chunk_size= Util.getShort(buffer, buffer_offset);
                
                if ((chunk_offset<0) || (chunk_offset>=authentikey_certificate_size))
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                if (((short)(chunk_offset+chunk_size))>authentikey_certificate_size)
                    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                Util.arrayCopyNonAtomic(authentikey_certificate, chunk_offset, buffer, (short)0, chunk_size);
                return chunk_size; 
                
            default:
                ISOException.throwIt(SW_INCORRECT_P2);
                return (short)0; 
        }
    }
    
    /**
     * This function locks the PKI config.
     * Once it is locked, it is not possible to modify private key, certificate or allowed_card_AID.
     *  
     *  ins: 
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: [none]
     *  return: [none]
     */
    private short lock_PKI(APDU apdu, byte[] buffer) {
        if (pin != null  && !pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        personalizationDone=true;
        return (short)0;
    }
    
    /**
     * This function performs a challenge-response to verify the authenticity of the device.
     * The challenge is made of three parts: 
     *          - a constant header
     *          - a 32-byte challenge provided by the requester
     *          - a 32-byte random nonce generated by the device
     * The response is the signature over this challenge. 
     * This signature can be verified with the certificate stored in the device.
     * 
     *  ins: 
     *  p1: 0x00 
     *  p2: 0x00 
     *  data: [challenge1(32b)]
     *  return: [challenge2(32b) | sig_size(2b) | sig]
     */
    private short challenge_response_pki(APDU apdu, byte[] buffer) {
        // todo: require PIN?
        if (!pin.isValidated())
            ISOException.throwIt(SW_UNAUTHORIZED);
        
        short bytesLeft = Util.makeShort((byte) 0x00, buffer[ISO7816.OFFSET_LC]);
        if (bytesLeft < (short)32)
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        
        //copy all data into array
        short offset=(short)0;
        Util.arrayCopyNonAtomic(PKI_CHALLENGE_MSG, (short)0, recvBuffer, offset, (short)PKI_CHALLENGE_MSG.length);
        offset+=PKI_CHALLENGE_MSG.length;
        randomData.generateData(recvBuffer, offset, (short)32);
        offset+=(short)32;
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, recvBuffer, offset, (short)32);
        offset+=(short)32;
         
        //sign challenge
        sigECDSA.init(authentikey_private, Signature.MODE_SIGN);
        short sign_size= sigECDSA.sign(recvBuffer, (short)0, offset, buffer, (short)34);
        Util.setShort(buffer, (short)32, sign_size);
        Util.arrayCopyNonAtomic(recvBuffer, (short)PKI_CHALLENGE_MSG.length, buffer, (short)0, (short)32);
        
        // verify response
        sigECDSA.init(authentikey_public, Signature.MODE_VERIFY);
        boolean is_valid= sigECDSA.verify(recvBuffer, (short)0, offset, buffer, (short)(34), sign_size);
        if (!is_valid)
            ISOException.throwIt(SW_SIGNATURE_INVALID);
        
        return (short)(32+2+sign_size);
    }

} // end of class JAVA_APPLET

