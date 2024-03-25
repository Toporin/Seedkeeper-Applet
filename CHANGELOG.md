# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

SeedKeeper applet full versions follows this format: vX.Y-Z.W where:
* X.Y refers to the PROTOCOL VERSION: changes that impact compatibility with the client side (e.g new functionalities, major patch...)
* Z.W refers to changes with no impact on compatibility of the client (e.g minor patches, optimizations...)

## Unreleased

## [0.2-0.1]

### Added

- Implement resetSecret(sid)
    This function reset a secret object in memory.

- add install parameters to define the size of secret storage memory
    For example, using Global Platform Pro:
    ``` .\gp.exe -f -install .\SeedKeeper.cap -params 0FFF ```

- add exportSecretToSatochip() function
    This function exports a secret for secure import to a Satochip.
    The secret is encrypted with a key is generated with ECDH, using the Satochip authentikey.
    Compared to the exportSecret() method, this method is executed in one phase, and the secret size is reduced to the minimum (max 64b).
    Only Masterseeds & 2FA secrets can be exported this way.

- add GetSeedKeeperStatus()
    This function retrieves information specific about the SeedKeeper applet
    running on the smartcard, and useful information about the status of
    current session such as:
    * number of secrets (objects) stored in the card
    * memory available
    * memory total
    * logs available
    * total logs event
    * last log

- add BIP32 support with getBIP32ExtendedKey()
    The function computes the Bip32 extended key derived from the master key and returns either the
    32-bytes x-coordinate of the public key, or the 32-bytes private key, signed by the authentikey.
    The Path for the derivation is provided in the apdu data.
    The function is mostly compatible with Satochip, with the addition of sid (secret_id of the masterseed) appended in the apdu data
    P2 parameters can include additional option masks:
    * 0x01: if set, use secure export otherwise use plain export
    * 0x02: if set, return privkey bytes, else public key
    * 0x04: if set, add final BIP85 HMAC derivation

- add xprv supportfor BIP32 in getBIP32ExtendedKey()    
    We use (option_flags & 0x02) bit set to 1 to indicate privkey derivation.
    If flag set to 0, we export the derived pubkey (as before).

- add [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki) support in getBIP32ExtendedKey()
    We use (option_flags & 0x04) bit set to 1 to indicate BIP85 derivation.
    The methods then returns 64 bytes of entropy, signed.
    If flag is set to 0, we export the derived BIP32 pubkey/privkey depending on (option_flags & 0x02) as before.

- add generateRandomSecret() 
    This function generates a secret randomly within the SeedKeeper.
    Secret_type should be in [SECRET_TYPE_MASTER_SEED, SECRET_TYPE_MASTER_PASSWORD, SECRET_TYPE_PRIVKEY, SECRET_TYPE_KEY]
    For symetric/asymetric secret/private keys, key_type provides the type of the key (AES/DES or Secp256k1...).
    if flag_save_enropy == 0x01: save a 'proof' that the secret used the external entropy provided
    Entropy is random data provided by the user and used in the secret random generation.
    Entropy size should be <= to the secret size to be generated
    
- add deriveMasterPassword()
    This function derives and export a secret (password) from a master password and provided salt.
    Derivation is done using HMAC-SHA512 using the salt as key and master password as message.
    Currently, only plaintext export is suported.

- add support for NFC policy
    NFC interface can be disabled or blocked through apdu command (INS 0x3E).
    By default, NFC is enabled. NFC policy can only be changed via the contact interface.
    Changing NFC policy requires to validate PIN first.
    NFC Policy:
    * NFC_ENABLED=0;
    * NFC_DISABLED=1; // can be re-enabled at any time
    * NFC_BLOCKED=2; // cannot be re-enabled except with reset factory!


### Changed

- Refactor 'reset to factory'.
    * previously: triggered by sending a specific APDU 5 times in a row, while removing the card between apdu
    * now: 'reset to factory' is triggered when the PIN and PUK are blocked (since the card is basically unusable at this stage anyway)

- in secret header (meta ata), assign available RFU1 byte to store secret subtype
    For each secret, we can provide a subtype with more context about the secret type.
    For SECRET_TYPE_MASTERSEED, that can be a slightly different format (including BIP39 meta data for example)
    For SECRE_TYPE_KEY, that can be the type of the key (AES-128/AES-256, entropy...)
    The subtype byte is loosely enforced by the applet, it is mainly used by client application  for context.

- importSecret() and exportSecret() memory optimization
    Previously, recvBuffer was used as a temporary buffer to store the full secret during import/export steps.
    Hence, recvBuffer size was a limiting factor when importing/exporting a secret.
    We remove the need to make a full copy of the secret to recvBuffer during import/export.
    Instead, we copy data directly from secret storage (om_secrets) in chunks.
    This allows to import/export secrets without size limitation (appart from the inherent limitation of storage capacity).
    For importSecret(), we need to provide the exact size of memory needed to store the (encrypted) secret in memory since memory is allocated in advance.
    This must be provided by the client in the init() phase. The size must take padding into acount.
    This size will be used to create object before any secret data is provided.
    If size is too small, an exception will be thrown. If size is too big, object will be clamped after import.

- simplify export policy
    Export policy can be:
    * SECRET_EXPORT_FORBIDDEN
    * SECRET_EXPORT_ALLOWED
    * SECRET_EXPORT_SECUREONLY
    * SECRET_EXPORT_AUTHENTICATED (RFU, not supported yet)
    Same policy is used for Secret usage, i.e. BIP32 derivation of masterseed or derivation of master password.

- Simplify PIN management:
    * Use only 1 PIN and 1 PUK
    * remove default PIN value, create & set PIN during setup
    * remove CreatePIN() function
    * remove ListPINs() function

### Fix
    
- patch spurious select issue (see https://github.com/Toporin/SatochipApplet/issues/11)

### Optimizations

- secure channel AES key: use TYPE_AES_TRANSIENT_DESELECT in priority
- secure channel EC key: use TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT in priority


## [0.1-0.1]

Initial version