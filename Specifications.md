# Introduction

This document provides some details about current Seedkeeper specification and implementation 

# Overview

Secrets are stored in Seedkeeper EEPROM memory. 
Each secret is composed of 2 parts:
* the secret header that contains metadata for the secret
* the (raw) secret data itself

The secret header has the following format:
* type(1b): defines the type of the secret
* origin(1b): defines the origin of the secret: imported of generated 
* export_control(1b): defines the export policy of the secret 
* nb_export_plain(1b): count the number of time the secret has been exported in plaintext
* nb_export_secure(1b): count the number of time the secret has been exported encrypted
* use_counter(1b): for some secret types, count the number of time the secret has been used
* fingerprint (4b):  a fingerprint of the raw secret data (without the header)
* subtype (1b): defines the subtype of secret (can be used to define multiple formats)
* RFU2 (1b): Reserved for future use 
* label_size(1b): size of label 
* label (max 64b): user provided label used to describe the secret 

Additionally, each secret can be identified by a unique 'sid' that is 2 bytes long and attributed by the chip applet on secret creation.

The secret header is stored in plaintext in the chip memory, but the PIN must be provided before any secret header can be exported.

The (raw) secret data is stored encrypted using AES-128 encryption with ECB mode (no initialization vector, 16-byte key generated randomly by the applet during instantiation) and PKCS#7 padding.

## origin values

```
    // origin
    private final static byte SECRET_ORIGIN_IMPORT_PLAIN= (byte) 0x01; 
    private final static byte SECRET_ORIGIN_IMPORT_SECURE = (byte) 0x02; 
    private final static byte SECRET_ORIGIN_ONCARD = (byte) 0x03; 
```

## export_control values
```
    // export policy 
    private final static byte SECRET_EXPORT_MASK = (byte) 0x03; // mask for the export controls
    private final static byte SECRET_EXPORT_FORBIDDEN = (byte) 0x00; // never allowed
    private final static byte SECRET_EXPORT_ALLOWED = (byte) 0x01; //plain or encrypted
    private final static byte SECRET_EXPORT_SECUREONLY = (byte) 0x02; // only encrypted with authentikey
    private final static byte SECRET_EXPORT_AUTHENTICATED = (byte) 0x03; // RFU: only encrypted with certified authentikey
```

# Secret types and their format

The following type values are currently supported (or Reserved for Future Use if marked 'RFU'):
* SECRET_TYPE_MASTER_SEED = 0x10: a masterseed is a raw byte array that is the root secret of bip32 hd wallet
* SECRET_TYPE_BIP39_MNEMONIC = 0x30: DEPRECATED, use SECRET_TYPE_MASTER_SEED with subtype 
* SECRET_TYPE_ELECTRUM_MNEMONIC =  0x40: for electrum mnemonic 
* SECRET_TYPE_SHAMIR_SECRET_SHARE =  0x50: for shamir secret shares (RFU)
* SECRET_TYPE_PRIVKEY = 0x60: for private keys of various format (RFU)
* SECRET_TYPE_PUBKEY = 0x70: for public keys of various format
* SECRET_TYPE_PUBKEY_AUTHENTICATED = 0x71: pubkey signed with known PKI subca (RFU)
* SECRET_TYPE_KEY= 0x80: secret keys for symmetric algorithm such as AES
* SECRET_TYPE_PASSWORD= 0x90: simple passwords 
* SECRET_TYPE_MASTER_PASSWORD= 0x91: master-password that can be derived to generate many passwords
* SECRET_TYPE_CERTIFICATE= 0xA0: certificates (RFU)
* SECRET_TYPE_2FA= 0xB0: for 2FA secret 
* SECRET_TYPE_BITCOIN_DESCRIPTOR= 0xC0: for bitcoin descriptor (RFU)

the default subtype is 0x00:
* private final static byte SECRET_SUBTYPE_DEFAULT = (byte) 0x00;

Some secret types support multiple subtypes or formats that are detailed below.

## SECRET_TYPE_MASTER_SEED format

* with subtype SECRET_SUBTYPE_DEFAULT : [ masterseed_size(1b) | masterseed_bytes ]

* with subtype SECRET_SUBTYPE_BIP39 (0x01): [ masterseed_size(1b) | masterseed_bytes | wordlist_selector(1b) | entropy_size(1b) | entropy(<=32b) | passphrase_size(1b) | passphrase] where entropy is 16-32 bytes as defined in BIP39 (this format is backward compatible with SECRET_TYPE_MASTER_SEED)

## SECRET_TYPE_BIP39_MNEMONIC & SECRET_TYPE_ELECTRUM_MNEMONIC format

* with subtype SECRET_SUBTYPE_DEFAULT : [ mnemonic_size(1b) | mnemonic_bytes | passphrase_size(1b) | passphrase_bytes | descriptor_size(2b) | wallet_descriptor] where 
	* mnemonic_bytes is the utf-8 encoding of the 12-24 words mnemonic (in canonical format)
	* passphrase_bytes is the utf-8 encoding of the passphrase (optional)
	* wallet_descriptor is a wallet descriptor (optional)

## SECRET_TYPE_PUBKEY

* with subtype SECRET_SUBTYPE_DEFAULT: [raw_pubkey_bytes] where raw_pubkey_bytes is the byte array representation of a  secp256k1 pubkey in compressed (0x02 or 0x03) or uncompressed (0x04) format.


## SECRET_TYPE_KEY

* with subtype SECRET_SUBTYPE_DEFAULT: [key_size(1b) | raw_key_bytes] where raw_key_bytes are the raw bytes of the secret key

* with subtype SECRET_SUBTYPE_ENTROPY (0x10): [size_entropy(1b) | external_entropy(entropy_size) | internal_entropy(secret_size)] where a generated secret is the sha512(external_entropy | internal_entropy) trimmed to first secret_size bytes if secret_size<64


## SECRET_TYPE_PASSWORD

* with subtype SECRET_SUBTYPE_DEFAULT: [password_size(1b) | password_bytes | login_size(1b) | login_bytes | url_size(1b) | url_bytes ]where 
	* password_bytes is the utf-8 encoding of the password
	* login_bytes is the utf-8 encoding of the login (optional)
	* url_bytes is the utf-8 encoding of the url (optional)

## SECRET_TYPE_MASTER_PASSWORD

* with subtype SECRET_SUBTYPE_DEFAULT: [master_password_size(1b) | raw_master_password_bytes] where
	* raw_master_password_bytes is the raw bytes of the master password

## SECRET_TYPE_BITCOIN_DESCRIPTOR

* with subtype SECRET_SUBTYPE_DEFAULT: [descriptor_size(2b) | raw_descriptor_bytes] where 
	* descriptor_size is 2 bytes long since a descriptor size can exceed 256 bytes.
	* raw_descriptor_bytes are the utf-8 encoding of the descriptor

# Compatibility between Seedkeeper v0.1 and v0.2

Seedkeeper v0.2 is mostly backward compatible with Seedkeepr v0.1. 

The main incompatibilities are:
* the Factory Reset method is different: factory reset in v0.2 is triggered by blocking the PIN and the PUK (entering wrong values multiple times), instead of sending a specific RESET command and removing card in v0.1
* For the importSecret(APDU apdu, byte[] buffer) function: in v0.2 we need to provide the secret_size (2bytes) in the init call as memory must be allocated before importing the secret (for v0.1, this is not required, but it can be provided anyway). 
	* This secret_size is the size that the **encrypted** secret will occupy in memory (using AES ECB with **padding**).
	* For secure import, secret is already encrypted, thus secret_size is simply the size of the encrypted secret (in bytes)
	* For plain import, secret will be encrypted in memory, so a padding of (AES_BLOCKSIZE - plain_secret_size%AES_BLOCKSIZE) must be added.
* In v0.2, a specific function exportSecretToSatochip() must be used to export an encrypted secret (masterseed or 2FA secret) to a satochip.

Seedkeeper v0.2 also add new functionalities that are NOT suppported in v0.1:
* Erase a secret
* Derive a Masterseed to get a bip32 extendedkey (pubkey, privkey, xpub, xpriv, bip85) using getBIP32ExtendedKey()
* Derive a Master Password using deriveMasterPassword()
* getSeedKeeperStatus() returns specific info such as memory usage
* generateRandomSecret() to generate a secret randomly within the SeedKeeper, using entropy from user as input. In v0.1, generate2FASecret() and generateMasterseed() can be used instead.
* NFC policy to disable/enable NFC

In Seedkeeper v0.2, some secret formats are deprecated and should be avoided (although they are still supported for backward compatibility):
* SECRET_TYPE_BIP39_MNEMONIC: use SECRET_TYPE_MASTER_SEED with subtypes SECRET_SUBTYPE_BIP39 (0x01) instead, as this format is more compact and allows to store the masterseed (bytes) and to recover the human readable mnemonic (words)

## Client support for backward compatibility

Applications should be able to create, import, export and display the following secret types (and subtypes):
* SECRET_TYPE_MASTER_SEED with subtypes:
	* SECRET_SUBTYPE_BIP39 (0x01)
* SECRET_TYPE_PUBKEY
* SECRET_TYPE_PASSWORD

To ensure backward compatibility, applications should be able to parse and display secrets exported in deprecated formats:
* SECRET_TYPE_MASTER_SEED
	* with subtypes SECRET_SUBTYPE_DEFAULT (that is, without BIP39/passphrase metadata)
* SECRET_TYPE_BIP39_MNEMONIC type
* SECRET_TYPE_ELECTRUM_MNEMONIC type
* SECRET_TYPE_KEY
	* with subtype SECRET_SUBTYPE_DEFAULT
	* with subtype SECRET_SUBTYPE_ENTROPY

These (deprecated) formats were used in the original (Seedkeeper-tool)[https://github.com/Toporin/Seedkeeper-Tool/releases/tag/v0.1.3] that only supports Seedkeeper v0.1.


When no format is specified/expected, the display of raw bytes can be done in hexadecimal.
