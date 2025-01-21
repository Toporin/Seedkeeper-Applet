# Seedkeeper-Applet
Open source javacard applet implementing a secure vault. Store your most precious secrets, including seeds, masterseed and others inside a secure chip, protected by a PIN code.

# Introduction

Traditionally, cryptocurrency users have used a simple pen and paper to keep a backup copy of their hardware wallet seed. 
While this simple method works relatively well, it has also signifiant drawbacks: 
* A piece of paper can be easily lost or destroyed
* The seed is usually written in plaintext, since encryption is not practical (and how do you store the encryption key anyway?)

A slightly more sophisticated way of securing your seed backup has been developed in the form of metal plates that are fire and water-proof.
But the user is still left with the difficulty of protecting the seed from malicious unwanted eyes.
And the challenge is only getting worse if you want to make multiple backups...

With a SeedKeeper, Seeds are stored in the smartcard secure memory and can only be accessed by their legitimate owner using a short, easy-to-remember, secret PIN code. SeedKeeper is easy to use yet powerful; it is robust yet affordable; and last but not least, it is completely open-source. 
SeedKeeper can be conveniently used in comnbination with a Satochip hardware wallet to serve as a secure backup. And you can use multiple SeedKeeper backups without compromising security!

# A few definitions

In order to clarify concepts, here are a few terms that will be use throughout this manual:

* PIN code: a 4-16 characters password used to unlock a SeedKeeper or Satochip. Any sensitive command requires to unlock the PIN device first. After the wrong PIN is input several times (typically 5), the device bricks itself and cannot be used anymore! 
* Seed: is the generic term to designate the secret data that is used to setup a wallet and access funds. A seed can take the form of a Mnemonic list or raw bytes (Masterseed).
* Mnemonic: is a human-readable list of 12 to 24 words that allows to generate or recover a wallet and spend the funds.
* Masterseed: is a 16 to 32 bytes secret derived from the Mnemonic. It is this value that is ultimately used as input to the BIP32 derivation process.
* Authentikey: is a public/private elliptic curve keypair that is unique per SeedKeeper device (and Satochip) and that can be used to authenticate a device and initiate communication with it.
* 2FA secret: is 20-byte random secret that can be used in a Satochip as second-factor authentication. If 2FA is enabled, all transactions must be approved on a second device such as a smartphone.
* Truststore: in the SeedKeeper-Tool application, the Truststore keeps a list of public key authentikeys for each SeedKeeper device connected so far. The Trustore is cleared upon application closing.
* SeedKeeper-Tool: this application used to communicate with a SeedKeeper

# SeedKeeper overview

The main purpose of a SeedKeeper is to securely store and backup seeds. 
On a basic level, here are the main actions you can perform on a seed:
* Import an existing seed on the SeedKeeper
* Generate a new (random) Mnenomic with the SeedKeeper-Tool and store it on the SeedKeeper
* Generate a new (random) Masterseed directly on the SeedKeeper
* Export a seed stored in the SeedKeeper to setup a new wallet

A SeedKeeper can store several seeds in its secure memory (the exact number depends on their size, but it can exceed several dozen).
A label can be attached to each seed stored in secure memory. This can be used e.g. to provide a short description in less than 128 characters.

A seed can be exported in two ways, as defined during seed creation:
* In plaintext: the seed is shown in plaintext on the SeedKeeper-Tool and can be copied to any wallet
* In encrypted form: the seed is encrypted for a specific device based on the authentikey, and can only be exported for that specific device.

The export in encrypted export is obviously more secure and it also allows end-to-end seed encryption, where the seed is generated on-card in a SeedKeeper then exported encrypted to any number of backup device and finally to a Satochip hardware wallet. Note however that encrypted export only works with compatible devices ( SeedKeeper and Satochip currently). Note also that if a seed is marked as 'Encrypted export only', it cannot be exported in plaintext for security!

For backup purpose, it is possible to export all the secrets stored in a SeedKeeper to another SeedKeeper. The procedure is similar to a seed export, except that all the secrets are exported in an encrypted form. An arbitrary number of backup can be performed that way.

# SeedKeeper secure pairing

The secure pairing allows 2 devices (SeedKeeper, Satochip or any compatible device in the future) to authenticate each other and generate a shared secret key to communicate securely. This will allow them to exchange seeds and other data. To achieve this, the two devices needs to exchange their authentikey and store the other device's authentikey in their secure memory. 
To simplify this process, each time a card is inserted, its authentikey is requested by the SeedKeeper-Tool and stored in a temporary array called the Truststore. 
When a user wants to export a seed from a device A to another device B, he selects B's authentikey in the 'Export a Secret' menu option. After export, the encrypted data is available in JSON format  

# How to use your SeedKeeper?

Current applications available to be use with a Seedkeeper:
* Windows, Linux & Mac: [Sato-Tool](https://github.com/Toporin/Satochip-Utils)
* Android app: [Google Play](https://play.google.com/store/apps/details?id=org.satochip.seedkeeper&hl=en), [Github](https://github.com/Toporin/Seedkeeper-Android)
* iOS app: [App store](https://apps.apple.com/be/app/seedkeeper/id6502836060), [Github](https://github.com/Toporin/Seedkeeper-iOS)
* For developers: there is a Command Line Interface available with pysatochip library: [Github](https://github.com/Toporin/pysatochip), [Pypi](https://pypi.org/project/pysatochip/)

To use your SeedKeeper with a computer, simply connect a card reader and insert the SeedKeeper in it, then run the Sato-Tool on your computer. If you are on Linux, you may need to install the smartcard driver if the card is not detected (for example on Ubuntu: "sudo apt install pcscd"). 
On the first usage, you will need to initialize the card by defining a PIN code and optionnaly a label to identify the card. On the subsequent use, you will have to enter your PIN code in order to use your SeedKeeper, so be sure to memorize this PIN correctly!

On a smartphone, you can connect to the card through NFC.

# How to use SeedKeeper with your Satochip?

You can import a BIP39 mnemonic, an Electrum mnemonic or the raw Masterseed into a Satochip. 
Note that it is not recommended to import an Electrum mnemonic into a hardware wallet (even though it is possible) as it is not standard and can create compatibility issues.
A Mnemonic can be imported in plaintext only, using any application supporting Satochip for the import (e.g. SeedKeeper-Tool, Electrum-Satochip, Electron Cash, Satochip-Bridge...).
A Masterseed can be imported encrypted using the SeedKeeper-Tool ('Import a Secret' > 'Secure import from json'). In this case, the encrypted Masterseed can be obtained from the export menu after pairing the SeedKeeper with the Satochip.

You can import a seed into a Satochip either in plaintext or encrypted. Simply insert the Satochip and use the same menu option as for seed import to a SeedKeeper (you will see that only the menu options available for a Satochip will be enabled). If the seed is in plaintext, you can use any application supporting Satochip for the import (e.g. Electrum-Satochip, Electron Cash, Satochip-Bridge...).

Note that encrypted seed import is only supported by Satochip v0.12 (and higher).

# Supported hardware

For supported hardware, refer to the [Satochip applet repository](https://github.com/Toporin/SatoChipApplet).

# Buidl & install

## Building using Ant (legacy)

You can build the javacard CAP files or use the last [release](https://github.com/Toporin/Seedkeeper-Applet/releases).

To generate the CAP file from the sources, you can use the [ant-javacard](https://github.com/martinpaljak/ant-javacard) Ant task (see the instructions on the ant-javacard github repository).

For detailed build and installation, refer to the [Satochip applet repository](https://github.com/Toporin/SatoChipApplet).

## Building using Gradle (new)

The project can also be built using Gradle with the [Fidesmo Javacard Gradle plugin](https://github.com/fidesmo/gradle-javacard).
Using this approach allows to load the NDEF applet at the same time (allows to automatically open the right application on Android by simply tapping the card).

For compiling the javacard code, you first need to download the javacard SDK into the project in the `sdks` folder:
```
git submodule add https://github.com/martinpaljak/oracle_javacard_sdks sdks
```

Then you must set the JavaCard HOME. The gradle.properties file has a setting with the property "com.fidesmo.gradle.javacard.home" set to the correct path.

To compile the javacard code and generate a cap file, simply run `./gradlew convertJavacard`. The cap file will be compiled in the `build/javacard/org/seedkeeper/applet` folder.

To load the cap file into a blank smart card, connect a card reader with the card inserted and run `./gradlew install`

# SDK

Several libraries are available to simplify integration of SeedKeeper with client applications:
* Python: Pysatochip (also availabl in [pypi](https://pypi.org/project/pysatochip/))
* Java/Kotlin: [Satochip-Java](https://github.com/Toporin/Satochip-Java)
* Swift:  [SatochipSwift](https://github.com/Toporin/SatochipSwift)

# Tests

Python unit tests are available through the [pysatochip module](https://github.com/Toporin/pysatochip).

The unit tests can be performed using:
```python -m unittest -v test_seedkeeper```

# License

This application is distributed under the GNU Affero General Public License version 3.

Some parts of the code may be licensed under a different (MIT-like) license. [Contact me](mailto:satochip.wallet@gmail.com) if you feel that some license combination is inappropriate.