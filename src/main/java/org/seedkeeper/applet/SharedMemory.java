// based on https://github.com/status-im/status-keycard/blob/146c049b45c2c20989214d2b37818e7b6222b0dd/src/main/java/im/status/keycard/SharedMemory.java
package org.seedkeeper.applet;

import javacard.security.*;

/**
 * Keep references to data structures shared across applet instances of this package.
 */
public class SharedMemory {

  /** The NDEF data file. Read through the NDEFApplet. **/
  static final short MAX_NDEF_DATA_FILE_SIZE = 224;

  // im.status.ethereum
  // static final byte[] ndefDataFile = {
  //     (byte) 0x26,
  //     (byte) 0x00, (byte) 0x24, (byte) 0xd4, (byte) 0x0f, (byte) 0x12, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
  //     (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d,
  //     (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x69, (byte) 0x6d, (byte) 0x2e, (byte) 0x73,
  //     (byte) 0x74, (byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x73, (byte) 0x2e, (byte) 0x65, (byte) 0x74,
  //     (byte) 0x68, (byte) 0x65, (byte) 0x72, (byte) 0x65, (byte) 0x75, (byte) 0x6d
  // };

  // org.satochip.satodimeapp
  // static final byte[] ndefDataFile = {
  //   (byte) 0x2c, 
  //   (byte) 0x00, (byte) 0x2A, (byte) 0xd4, (byte) 0x0f, (byte) 0x18, (byte) 0x61, (byte) 0x6e, (byte) 0x64, 
  //   (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f, (byte) 0x6d, 
  //   (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x6f, (byte) 0x72, (byte) 0x67, (byte) 0x2e, 
  //   (byte) 0x73, (byte) 0x61, (byte) 0x74, (byte) 0x6f, (byte) 0x63, (byte) 0x68, (byte) 0x69, (byte) 0x70, 
  //   (byte) 0x2e, (byte) 0x73, (byte) 0x61, (byte) 0x74, (byte) 0x6f, (byte) 0x64, (byte) 0x69, (byte) 0x6d, 
  //   (byte) 0x65, (byte) 0x61, (byte) 0x70, (byte) 0x70
  // };

  // org.satochip.seedkeeperapp
  // static final byte[] ndefDataFile = {
  //   (byte) 0x2e, (byte) 0x00, (byte) 0x2c, (byte) 0xd4, (byte) 0x0f, (byte) 0x1a, (byte) 0x61, (byte) 0x6e, 
  //   (byte) 0x64, (byte) 0x72, (byte) 0x6f, (byte) 0x69, (byte) 0x64, (byte) 0x2e, (byte) 0x63, (byte) 0x6f,
  //   (byte) 0x6d, (byte) 0x3a, (byte) 0x70, (byte) 0x6b, (byte) 0x67, (byte) 0x6f, (byte) 0x72, (byte) 0x67,
  //   (byte) 0x2e, (byte) 0x73, (byte) 0x61, (byte) 0x74, (byte) 0x6f, (byte) 0x63, (byte) 0x68, (byte) 0x69,
  //   (byte) 0x70, (byte) 0x2e, (byte) 0x73, (byte) 0x65, (byte) 0x65, (byte) 0x64, (byte) 0x6b, (byte) 0x65,
  //   (byte) 0x65, (byte) 0x70, (byte) 0x65, (byte) 0x72, (byte) 0x61, (byte) 0x70, (byte) 0x70
  // };

  // https://www.google.com
  static final byte[] ndefDataFile = {
    (byte) 0x11, (byte) 0x00, (byte) 0x0f, (byte) 0xD1, (byte) 0x01, (byte) 0x0B, (byte) 0x55, (byte) 0x02,
    (byte) 0x67, (byte) 0x6F, (byte) 0x6F, (byte) 0x67, (byte) 0x6C, (byte) 0x65, (byte) 0x2E, (byte) 0x63, 
    (byte) 0x6F, (byte) 0x6D
  };

}