import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;

public class AES {

  private final byte[][] sBox = {
    { 0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76 },
    { (byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72, (byte) 0xc0 },
    { (byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15 },
    { 0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96, 0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75 },
    { 0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84 },
    { 0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf },
    { (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte) 0x9f, (byte) 0xa8 },
    { 0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2 },
    { (byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
    { 0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee, (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb },
    { (byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79 },
    { (byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56, (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08 },
    { (byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a },
    { 0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e },
    { (byte) 0xe1, (byte) 0xf8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf },
    { (byte) 0x8c, (byte) 0xa1, (byte) 0x89, (byte) 0x0d, (byte) 0xbf, (byte) 0xe6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2d, (byte) 0x0f, (byte) 0xb0, (byte) 0x54, (byte) 0xbb, (byte) 0x16 }
  };

  private final byte[][] invSBox = {
    {0x52, 0x09, 0x6a, (byte)0xd5, 0x30, 0x36, (byte)0xa5, 0x38, (byte)0xbf, 0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb}, 
    {0x7c, (byte)0xe3, 0x39, (byte)0x82, (byte)0x9b, 0x2f, (byte)0xff, (byte)0x87, 0x34, (byte)0x8e, 0x43, 0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb}, 
    {0x54, 0x7b, (byte)0x94, 0x32, (byte)0xa6, (byte)0xc2, 0x23, 0x3d, (byte)0xee, 0x4c, (byte)0x95, 0x0b, 0x42, (byte)0xfa, (byte)0xc3, 0x4e}, 
    {0x08, 0x2e, (byte)0xa1, 0x66, 0x28, (byte)0xd9, 0x24, (byte)0xb2, 0x76, 0x5b, (byte)0xa2, 0x49, 0x6d, (byte)0x8b, (byte)0xd1, 0x25}, 
    {0x72, (byte)0xf8, (byte)0xf6, 0x64, (byte)0x86, 0x68, (byte)0x98, 0x16, (byte)0xd4, (byte)0xa4, 0x5c, (byte)0xcc, 0x5d, 0x65, (byte)0xb6, (byte)0x92}, 
    {0x6c, 0x70, 0x48, 0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, 0x5e, 0x15, 0x46, 0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84}, 
    {(byte)0x90, (byte)0xd8, (byte)0xab, 0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, 0x0a, (byte)0xf7, (byte)0xe4, 0x58, 0x05, (byte)0xb8, (byte)0xb3, 0x45, 0x06}, 
    {(byte)0xd0, 0x2c, 0x1e, (byte)0x8f, (byte)0xca, 0x3f, 0x0f, 0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, 0x03, 0x01, 0x13, (byte)0x8a, 0x6b}, 
    {0x3a, (byte)0x91, 0x11, 0x41, 0x4f, 0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, 0x73}, 
    {(byte)0x96, (byte)0xac, 0x74, 0x22, (byte)0xe7, (byte)0xad, 0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, 0x37, (byte)0xe8, 0x1c, 0x75, (byte)0xdf, 0x6e}, 
    {0x47, (byte)0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte)0xc5, (byte)0x89, 0x6f, (byte)0xb7, 0x62, 0x0e, (byte)0xaa, 0x18, (byte)0xbe, 0x1b}, 
    {(byte)0xfc, 0x56, 0x3e, 0x4b, (byte)0xc6, (byte)0xd2, 0x79, 0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, 0x78, (byte)0xcd, 0x5a, (byte)0xf4}, 
    {0x1f, (byte)0xdd, (byte)0xa8, 0x33, (byte)0x88, 0x07, (byte)0xc7, 0x31, (byte)0xb1, 0x12, 0x10, 0x59, 0x27, (byte)0x80, (byte)0xec, 0x5f}, 
    {0x60, 0x51, 0x7f, (byte)0xa9, 0x19, (byte)0xb5, 0x4a, 0x0d, 0x2d, (byte)0xe5, 0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef}, 
    {(byte)0xa0, (byte)0xe0, 0x3b, 0x4d, (byte)0xae, 0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, 0x3c, (byte)0x83, 0x53, (byte)0x99, 0x61}, 
    {0x17, 0x2b, 0x04, 0x7e, (byte)0xba, 0x77, (byte)0xd6, 0x26, (byte)0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
  };

  private final byte[][] predefinedMatrix = {
    { 0x02, 0x03, 0x01, 0x01 },
    { 0x01, 0x02, 0x03, 0x01 },
    { 0x01, 0x01, 0x02, 0x03 },
    { 0x03, 0x01, 0x01, 0x02 }
  };

  private final byte[][] invPredefinedMatrix = {
    {0x0e, 0x0b, 0x0d, 0x09},
    {0x09, 0x0e, 0x0b, 0x0d},
    {0x0d, 0x09, 0x0e, 0x0b},
    {0x0b, 0x0d, 0x09, 0x0e}
  };

  private final byte[][] expandedKey = {
    { (byte) 0x73, (byte) 0x65, (byte) 0x63, (byte) 0x73 },
    { (byte) 0x65, (byte) 0x74, (byte) 0x72, (byte) 0x65 },
    { (byte) 0x63, (byte) 0x73, (byte) 0x65, (byte) 0x63 },
    { (byte) 0x72, (byte) 0x65, (byte) 0x74, (byte) 0x72 },

    { (byte) 0x3f, (byte) 0x5a, (byte) 0x39, (byte) 0x4a },
    { (byte) 0x9e, (byte) 0xea, (byte) 0x98, (byte) 0xfd },
    { (byte) 0x23, (byte) 0x50, (byte) 0x35, (byte) 0x56 },
    { (byte) 0xfd, (byte) 0x98, (byte) 0xec, (byte) 0x9e },

    { (byte) 0x69, (byte) 0x33, (byte) 0x0a, (byte) 0x40 },
    { (byte) 0x2f, (byte) 0xc5, (byte) 0x5d, (byte) 0xa0 },
    { (byte) 0x28, (byte) 0x78, (byte) 0x4d, (byte) 0x1b },
    { (byte) 0x2b, (byte) 0xb3, (byte) 0x5f, (byte) 0xc1 },

    { (byte) 0x8d, (byte) 0xbe, (byte) 0xb4, (byte) 0xf4 },
    { (byte) 0x80, (byte) 0x45, (byte) 0x18, (byte) 0xb8 },
    { (byte) 0x50, (byte) 0x28, (byte) 0x65, (byte) 0x7e },
    { (byte) 0x22, (byte) 0x91, (byte) 0xce, (byte) 0x0f },

    { (byte) 0xe9, (byte) 0x57, (byte) 0xe3, (byte) 0x17 },
    { (byte) 0x73, (byte) 0x36, (byte) 0x2e, (byte) 0x96 },
    { (byte) 0x26, (byte) 0x0e, (byte) 0x6b, (byte) 0x15 },
    { (byte) 0x9d, (byte) 0x0c, (byte) 0xc2, (byte) 0xcd },

    { (byte) 0x69, (byte) 0x3e, (byte) 0xdd, (byte) 0xca },
    { (byte) 0x2a, (byte) 0x1c, (byte) 0x32, (byte) 0xa4 },
    { (byte) 0x9b, (byte) 0x95, (byte) 0xfe, (byte) 0xeb },
    { (byte) 0x6d, (byte) 0x61, (byte) 0xa3, (byte) 0x6e },

    { (byte) 0x00, (byte) 0x3e, (byte) 0xe3, (byte) 0x29 },
    { (byte) 0xc3, (byte) 0xdf, (byte) 0xed, (byte) 0x49 },
    { (byte) 0x04, (byte) 0x91, (byte) 0x6f, (byte) 0x84 },
    { (byte) 0x19, (byte) 0x78, (byte) 0xdb, (byte) 0xb5 },

    { (byte) 0x7b, (byte) 0x45, (byte) 0xa6, (byte) 0x8f },
    { (byte) 0x9c, (byte) 0x43, (byte) 0xae, (byte) 0xe7 },
    { (byte) 0xd1, (byte) 0x40, (byte) 0x2f, (byte) 0xab },
    { (byte) 0xbc, (byte) 0xc4, (byte) 0x1f, (byte) 0xaa },

    { (byte) 0x6f, (byte) 0x2a, (byte) 0x8c, (byte) 0x03 },
    { (byte) 0xfe, (byte) 0xbd, (byte) 0x13, (byte) 0xf4 },
    { (byte) 0x7d, (byte) 0x3d, (byte) 0x12, (byte) 0xb9 },
    { (byte) 0xcf, (byte) 0x0b, (byte) 0x14, (byte) 0xbe },

    { (byte) 0xcb, (byte) 0xe1, (byte) 0x6d, (byte) 0x6e },
    { (byte) 0xa8, (byte) 0x15, (byte) 0x06, (byte) 0xf2 },
    { (byte) 0xd3, (byte) 0xee, (byte) 0xfc, (byte) 0x45 },
    { (byte) 0xb4, (byte) 0xbf, (byte) 0xab, (byte) 0x15 },

    { (byte) 0x74, (byte) 0x95, (byte) 0xf8, (byte) 0x96 },
    { (byte) 0xc6, (byte) 0xd3, (byte) 0xd5, (byte) 0x27 },
    { (byte) 0x8a, (byte) 0x64, (byte) 0x98, (byte) 0xdd },
    { (byte) 0x2b, (byte) 0x94, (byte) 0x3f, (byte) 0x2a },
  };

  public byte[] encrypt(byte[] key, byte[] data){
    byte[][] encryptedBlocks;
    byte[][] plaintextBlocks;
    byte[] returnVal;
    byte[][] state;
    byte[][] rdSubBytes;
    byte[][] rdShift;
    byte[][] rdMix;
    byte[][] rdSubKey;
    byte[][] rdAddKey;

    // byte[][] expandedKey = keyExpansion(key);

    // add 1 to account for partial block filled with remainder bytes;
    // in the case data length is multiple of 16, add 1 for padding block according to PKCS#7 standard
    int numberOfBlocks = (data.length / 16) + 1;
    int partialBlockLength = data.length % 16;
    // following PKCS#7 Standard where value of padding bytes equals the number of bytes needed to be added
    int valueOfPaddingBytes = 16 - partialBlockLength;
    byte[] paddingBytes = new byte[valueOfPaddingBytes];
    Arrays.fill(paddingBytes, (byte)valueOfPaddingBytes);

    // declare plaintext and encryptedBlocks
    plaintextBlocks = new byte[numberOfBlocks][16];
    encryptedBlocks = new byte[numberOfBlocks][16];

    int currentStartingIndex = 0;
    // break plaintext data into 16-byte blocks, except for last block
    for(int i = 0; i < numberOfBlocks - 1; i++){
      plaintextBlocks[i] = Arrays.copyOfRange(data, currentStartingIndex, currentStartingIndex + 16);
      currentStartingIndex += 16;
    }
    // for last block, copy remaining bytes in plaintext and then fill rest with padding bytes
    System.arraycopy(data, currentStartingIndex, plaintextBlocks[numberOfBlocks - 1], 0, partialBlockLength);
    System.arraycopy(paddingBytes, 0, plaintextBlocks[numberOfBlocks - 1], partialBlockLength, valueOfPaddingBytes);

    // encrypt each block
    for(int i = 0; i < numberOfBlocks; i++){

      state = to2DArray(plaintextBlocks[i]);
      // Round "0"
      rdSubKey = grabSubkey(expandedKey, 0);
      rdAddKey = addRoundKey(state, rdSubKey);
      // Rounds "1-9"
      for (int j = 1; j < 10; j++) {
        rdSubBytes = subBytes(rdAddKey);
        rdShift = shiftRows(rdSubBytes);
        rdMix = mixColumns(rdShift);
        rdSubKey = grabSubkey(expandedKey, j);
        rdAddKey = addRoundKey(rdMix, rdSubKey);
      }
      // Round 10
      rdSubBytes = subBytes(rdAddKey);
      rdShift = shiftRows(rdSubBytes);
      rdSubKey = grabSubkey(expandedKey, 10);
      rdAddKey = addRoundKey(rdShift, rdSubKey);

      encryptedBlocks[i] = to1DArray(rdAddKey);
    }

    // flatten encrypted blocks into 1D row major return val array
    returnVal = new byte[16*numberOfBlocks];
    int k = 0;  
    for (int i = 0; i < numberOfBlocks; i++) { 
        for (int j = 0; j < 16; j++) { 
            returnVal[k++] = encryptedBlocks[i][j]; 
        } 
    } 
    return returnVal;
  }

  public byte[] decrypt(byte[] key, byte[] data){
    byte[][] encryptedBlocks;
    byte[][] decryptedBlocks;
    byte[][] state;
    byte[][] rdInvSubBytes;
    byte[][] rdInvShift;
    byte[][] rdInvMix;
    byte[][] rdSubKey;
    byte[][] rdAddKey;
    byte[] returnVal;

    // byte[][] expandedKey = keyExpansion(key);

    // data will be a multiple of 16
    int numberOfBlocks = data.length / 16;
    // declare decryptedBlocks and encryptedBlocks
    encryptedBlocks = new byte[numberOfBlocks][16];
    decryptedBlocks = new byte[numberOfBlocks][16];

    int currentStartingIndex = 0;
    // break encrypted data into 16-byte encrypted blocks
    for(int i = 0; i < numberOfBlocks; i++){
      encryptedBlocks[i] = Arrays.copyOfRange(data, currentStartingIndex, currentStartingIndex + 16);
      currentStartingIndex += 16;
    }

    // decrypt each block
    for(int i = 0; i < numberOfBlocks; i++){

      state = to2DArray(encryptedBlocks[i]);

      // Round 10
      rdSubKey = grabSubkey(expandedKey, 10);
      rdAddKey = addRoundKey(state, rdSubKey);
      rdInvShift = invShiftRows(rdAddKey);
      rdInvSubBytes = invSubBytes(rdInvShift);
      // Rounds 9 to 1
      for (int j = 9; j > 0; j--) {
        rdSubKey = grabSubkey(expandedKey, j);
        rdAddKey = addRoundKey(rdInvSubBytes, rdSubKey);
        rdInvMix = invMixColumns(rdAddKey);
        rdInvShift = invShiftRows(rdInvMix);
        rdInvSubBytes = invSubBytes(rdInvShift);
      }
      // Round "0"
      rdSubKey = grabSubkey(expandedKey, 0);
      rdAddKey = addRoundKey(rdInvSubBytes, rdSubKey);

      decryptedBlocks[i] = to1DArray(rdAddKey);
    }
    // flatten decrypted blocks into 1D row major return val array
    returnVal = new byte[(16*numberOfBlocks)];
    int k = 0;  
    for (int i = 0; i < numberOfBlocks; i++) { 
        for (int j = 0; j < 16; j++) { 
            returnVal[k++] = decryptedBlocks[i][j]; 
        } 
    } 
    // remove padding bytes
    byte paddingValue = returnVal[returnVal.length - 1];
    returnVal = Arrays.copyOfRange(returnVal, 0, returnVal.length - paddingValue);
    return returnVal;
  }

  private byte[][] keyExpansion(byte[] key) {
    byte[][] expandedKey = new byte[4][16];
    // for (int i = 0; i < 16; i++)
    // {
    // for (int j = 0; j < 4; j++) {
    // keyMatrix[j][i] = Integer.parseInt(key.substring((8 * i) + (2 * j), (8 * i) +
    // (2 * j + 2)), 16);
    // }
    // }
    return expandedKey;
  }

  /**
   * converts a 1D array to a 4x4 2D array column-major order
   * 
   * @param array the array to convert
   * @return the 2D array
   */
  private byte[][] to2DArray(byte[] array) {
    byte[][] matrix = new byte[4][4];
    for (int i = 0; i < 4; i++)
      for (int j = 0; j < 4; j++)
        matrix[j][i] = array[(i * 4) + j];
    return matrix;
  }

  /**
   * converts 2D 4x4 array to a 1D array, column major order mapping
   * 
   * @param matrix 2D 4x4 array
   * @return 1D array
   */
  private byte[] to1DArray(byte[][] matrix) {
    byte[] array = new byte[16];
    for (int i = 0; i < 4; i++) {
      for (int j = 0; j < 4; j++) {
        byte val = matrix[j][i];
        array[i * 4 + j] = val;
      }
    }
    return array;
  }

  /**
   * Grab the desired 4x4 subkey from the expanded key matrix
   * 
   * @param ekey  expanded key matrix
   * @param start current AES round; used to find row in expanded key to start
   *              extracting subkey
   * @return subkey matrix
   */
  private byte[][] grabSubkey(byte[][] ekey, int start) {
    byte[][] subkey = new byte[4][4];
    for (int i = 0; i < subkey.length; i++) {
      for (int j = 0; j < subkey.length; j++) {
        subkey[j][i] = ekey[4 * start + j][i];
      }
    }
    return subkey;
  }

  private byte[][] addRoundKey(byte[][] state, byte[][] rndKey) {
    byte[][] newState = new byte[4][4];
    for (int i = 0; i < newState.length; i++) {
      for (int j = 0; j < newState.length; j++) {
        newState[i][j] = (byte) (state[i][j] ^ rndKey[i][j]);
      }
    }
    return newState;
  }

  /**
   * map each byte in state matrix to new byte based on AES S-box
   * 
   * @param state current state matrix
   * @return state matrix after substitutions
   */
  private byte[][] subBytes(byte[][] state) {
    byte[][] newState = new byte[4][4];

    for (int i = 0; i < newState.length; i++) {
      for (int j = 0; j < newState.length; j++) {
        newState[i][j] = (byte) (
        // leftmost 4 bits of byte is the row index for s-box;
        // unless already int or long, shift operands in Java are converted to 4 byte
        // int;
        // to isolate the leftmost bits left shift 24 times to remove preceding bits,
        // then logical right shift 28 times
        // so 4 leftmost bits are the only remaining and can be read as its own number
        sBox[((state[i][j] << 24) >>> 28)]
        // rightmost 4 bits of byte is the column index for s-box;
        // unless already int or long, shift operands in Java are converted to 4 byte
        // int;
        // to isolate the rightmost bits left shift 28 times to remove preceding bits,
        // then logical right shift 28 times
        // so 4 rightmost bits are the only remaining and can be read as its own number
        [((state[i][j] << 28) >>> 28)]);
      }
    }
    return newState;
  }

  /**
   * performs permutation on state matrix through row shifts
   * 
   * @param state current state matrix
   * @return new state matrix
   */
  private byte[][] shiftRows(byte[][] state) {
    byte[][] newState = new byte[4][4];
    // row 1 --> no shifting
    newState[0] = state[0];
    // row 2 --> 1 byte left shift
    newState[1][0] = state[1][1];
    newState[1][1] = state[1][2];
    newState[1][2] = state[1][3];
    newState[1][3] = state[1][0];
    // row 3 --> 2 byte left shift
    newState[2][0] = state[2][2];
    newState[2][1] = state[2][3];
    newState[2][2] = state[2][0];
    newState[2][3] = state[2][1];
    // row 4 --> 3 byte left shift
    newState[3][0] = state[3][3];
    newState[3][1] = state[3][0];
    newState[3][2] = state[3][1];
    newState[3][3] = state[3][2];

    return newState;
  }

  /**
   * galois field GF(2^8) multiplication helper function for @multi;
   * GF multiplication by 2
   * @param x byte to multiply by 2
   * @return byte resulting from multiplication 
   */
  private byte multi2(byte x){
    byte leftmost = (byte) (x & 0x80);
    x = (byte) (x << 1);
    if (leftmost != 0) {
      x = (byte) (x ^ 0x1b);
    }
    return x;
  }

  /**
   * galois field GF(2^8) multiplication helper function for mixColumn
   * 
   * @param x byte from state matrix
   * @param y byte from predefined matrix (either 0x01, 0x02, 0x03, 0x0e, 0x0b, 0x0d, 0x09)
   * @return byte resulting from multiplication of elements in galois field
   */
  private byte multi(byte x, byte y) {
    byte val = 0;
    switch (y) {
      // multiply by 1 --> return byte
      case 0x01: {
        val = x;
        break;
      }
      // multiply by 2 --> shortcut: logical left shift 1; if logical left shift 1
      // dropped a 1,
      // XOR with 0x1b, which represents
      case 0x02: {
        val = multi2(x);
        break;
      }
      case 0x03: {
        val = (byte)(multi2(x) ^ x);
        break;
      }
      case 0x09: {
        val = (byte)(multi2(multi2(multi2(x))) ^ x);
        break;
      }
      case 0x0b: {
        val = (byte)(multi2((byte)(multi2(multi2(x)) ^ x))^x);
        break;
      }
      case 0x0d: {
        val = (byte)(multi2(multi2((byte)(multi2(x) ^ x)))^x);
        break;
      }
      case 0x0e: {
        val = (byte)(multi2((byte)(multi2((byte)(multi2(x) ^ x))^x)));
        break;
      }
    }
    return val;
  }

  private byte[][] mixColumns(byte[][] state) {
    byte[][] newState = new byte[4][4];
    for (int i = 0; i < newState.length; i++) {
      for (int j = 0; j < newState.length; j++) {
        newState[i][j] = (byte) (((byte) multi(state[0][j], predefinedMatrix[i][0]))
            ^ ((byte) multi(state[1][j], predefinedMatrix[i][1])) ^ ((byte) multi(state[2][j], predefinedMatrix[i][2]))
            ^ ((byte) multi(state[3][j], predefinedMatrix[i][3])));
      }
    }
    return newState;
  }

  /**
   * performs permutation on state matrix through right circular row shifts;
   * inverse of shift rows
   * @param state current state matrix
   * @return new state matrix
   */
  private byte[][] invShiftRows(byte[][] state) {
    byte[][] newState = new byte[4][4];
    // row 1 --> no shifting
    newState[0] = state[0];
    // row 2 --> 1 byte right shift
    newState[1][0] = state[1][3];
    newState[1][1] = state[1][0];
    newState[1][2] = state[1][1];
    newState[1][3] = state[1][2];
    // row 3 --> 2 byte right shift
    newState[2][0] = state[2][2];
    newState[2][1] = state[2][3];
    newState[2][2] = state[2][0];
    newState[2][3] = state[2][1];
    // row 4 --> 3 byte right shift
    newState[3][0] = state[3][1];
    newState[3][1] = state[3][2];
    newState[3][2] = state[3][3];
    newState[3][3] = state[3][0];

    return newState;
  }

  /**
   * map each byte in state matrix to new byte based on AES Inverse S-box
   * 
   * @param state current state matrix
   * @return state matrix after substitutions
   */
  private byte[][] invSubBytes(byte[][] state) {
    byte[][] newState = new byte[4][4];

    for (int i = 0; i < newState.length; i++) {
      for (int j = 0; j < newState.length; j++) {
        newState[i][j] = (byte) (
        // leftmost 4 bits of byte is the row index for inverse s-box;
        // unless already int or long, shift operands in Java are converted to 4 byte
        // int;
        // to isolate the leftmost bits left shift 24 times to remove preceding bits,
        // then logical right shift 28 times
        // so 4 leftmost bits are the only remaining and can be read as its own number
        invSBox[((state[i][j] << 24) >>> 28)]
        // rightmost 4 bits of byte is the column index for inverse s-box;
        // unless already int or long, shift operands in Java are converted to 4 byte
        // int;
        // to isolate the rightmost bits left shift 28 times to remove preceding bits,
        // then logical right shift 28 times
        // so 4 rightmost bits are the only remaining and can be read as its own number
        [((state[i][j] << 28) >>> 28)]);
      }
    }
    return newState;
  }

  private byte[][] invMixColumns(byte[][] state) {
    byte[][] newState = new byte[4][4];
    for (int i = 0; i < newState.length; i++) {
      for (int j = 0; j < newState.length; j++) {
        newState[i][j] = (byte) (((byte) multi(state[0][j], invPredefinedMatrix[i][0]))
            ^ ((byte) multi(state[1][j], invPredefinedMatrix[i][1])) ^ ((byte) multi(state[2][j], invPredefinedMatrix[i][2]))
            ^ ((byte) multi(state[3][j], invPredefinedMatrix[i][3])));
      }
    }
    return newState;
  }

}
