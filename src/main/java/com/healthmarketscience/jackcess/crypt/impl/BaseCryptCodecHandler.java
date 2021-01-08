/*
Copyright (c) 2010 Vladimir Berezniker

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.healthmarketscience.jackcess.crypt.impl;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import com.healthmarketscience.jackcess.crypt.util.StreamCipherCompat;
import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.CodecHandler;
import com.healthmarketscience.jackcess.impl.PageChannel;
import com.healthmarketscience.jackcess.impl.TempBufferHolder;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;


/**
 * Common CodecHandler support.
 *
 * @author Vladimir Berezniker
 */
public abstract class BaseCryptCodecHandler implements CodecHandler
{
  public static final boolean CIPHER_DECRYPT_MODE = false;
  public static final boolean CIPHER_ENCRYPT_MODE = true;

  private final PageChannel _channel;
  private final byte[] _encodingKey;
  private final KeyCache<CipherParameters> _paramCache =
    new KeyCache<CipherParameters>() {
      @Override protected CipherParameters computeKey(int pageNumber) {
        return computeCipherParams(pageNumber);
      }
    };
  private TempBufferHolder _tempBufH;

  protected BaseCryptCodecHandler(PageChannel channel, byte[] encodingKey) {
    _channel = channel;
    _encodingKey = encodingKey;
  }

  protected CipherParameters getCipherParams(int pageNumber) {
    return _paramCache.get(pageNumber);
  }

  protected byte[] getEncodingKey() {
    return _encodingKey;
  }

  protected StreamCipherCompat getStreamCipher() {
    throw new UnsupportedOperationException();
  }

  protected BufferedBlockCipher getBlockCipher() {
    throw new UnsupportedOperationException();
  }

  protected ByteBuffer getTempBuffer() {
    if(_tempBufH == null) {
      _tempBufH = TempBufferHolder.newHolder(TempBufferHolder.Type.SOFT, true);
    }
    ByteBuffer tempBuf = _tempBufH.getPageBuffer(_channel);
    tempBuf.clear();
    return tempBuf;
  }

  /**
   * Decrypts the given buffer using a stream cipher.
   */
  protected void streamDecrypt(ByteBuffer buffer, int pageNumber) {
    StreamCipherCompat cipher = decryptInit(getStreamCipher(),
                                      getCipherParams(pageNumber));

    byte[] array = buffer.array();
    cipher.processStreamBytes(array, 0, array.length, array, 0);
  }

  /**
   * Encrypts the given buffer using a stream cipher and returns the encrypted
   * buffer.
   */
  protected ByteBuffer streamEncrypt(
      ByteBuffer buffer, int pageNumber, int pageOffset)
  {
    StreamCipherCompat cipher = encryptInit(getStreamCipher(),
                                      getCipherParams(pageNumber));

    // note, we always start encoding at offset 0 so that we apply the cipher
    // to the correct part of the stream.  however, we can stop when we get to
    // the limit.
    int limit = buffer.limit();
    ByteBuffer encodeBuf = getTempBuffer();
    cipher.processStreamBytes(buffer.array(), 0, limit, encodeBuf.array(), 0);
    return encodeBuf;
  }

  /**
   * Decrypts the given buffer using a block cipher.
   */
  protected void blockDecrypt(ByteBuffer inPage, ByteBuffer outPage,
                              int pageNumber)
  {
    BufferedBlockCipher cipher = decryptInit(getBlockCipher(),
                                             getCipherParams(pageNumber));

    try {
      byte[] inArray = inPage.array();
      int inLen = inArray.length;
      byte[] outArray = outPage.array();
      processBytesFully(cipher, inArray, fill(outArray, 0), inLen);
    } catch(InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Encrypts the given buffer using a block cipher and returns the encrypted
   * buffer.
   */
  protected ByteBuffer blockEncrypt(ByteBuffer buffer, int pageNumber)
  {
    BufferedBlockCipher cipher = encryptInit(getBlockCipher(),
                                             getCipherParams(pageNumber));

    try {
      byte[] inArray = buffer.array();
      int inLen = buffer.limit();
      ByteBuffer encodeBuf = getTempBuffer();
      processBytesFully(cipher, inArray, fill(encodeBuf.array(), 0), inLen);
      return encodeBuf;
    } catch(InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public String toString() {
    return getClass().getSimpleName();
  }

  /**
   * Inits the given cipher for decryption with the given params.
   */
  protected static StreamCipherCompat decryptInit(
      StreamCipherCompat cipher, CipherParameters params)
  {
    cipher.init(CIPHER_DECRYPT_MODE, params);
    return cipher;
  }

  /**
   * Inits the given cipher for encryption with the given params.
   */
  protected static StreamCipherCompat encryptInit(
      StreamCipherCompat cipher, CipherParameters params)
  {
    cipher.init(CIPHER_ENCRYPT_MODE, params);
    return cipher;
  }

  /**
   * Inits the given cipher for decryption with the given params.
   */
  protected static BufferedBlockCipher decryptInit(
      BufferedBlockCipher cipher, CipherParameters params)
  {
    cipher.init(CIPHER_DECRYPT_MODE, params);
    return cipher;
  }

  /**
   * Inits the given cipher for encryption with the given params.
   */
  protected static BufferedBlockCipher encryptInit(
      BufferedBlockCipher cipher, CipherParameters params)
  {
    cipher.init(CIPHER_ENCRYPT_MODE, params);
    return cipher;
  }

  /**
   * Decrypts the given bytes using a stream cipher into a new byte[].
   */
  protected static byte[] decryptBytes(StreamCipherCompat cipher, byte[] encBytes)
  {
    byte[] bytes = new byte[encBytes.length];
    cipher.processStreamBytes(encBytes, 0, encBytes.length, bytes, 0);
    return bytes;
  }

  /**
   * Decrypts the given bytes using a block cipher configured with the given
   * key and IV into a new byte[].
   */
  protected byte[] blockDecryptBytes(byte[] keyBytes, byte[] iv, byte[] encBytes)
  {
    BufferedBlockCipher cipher = decryptInit(
        getBlockCipher(), new ParametersWithIV(new KeyParameter(keyBytes), iv));
    return decryptBytes(cipher, encBytes);
  }

  /**
   * Decrypts the given bytes using a block cipher into a new byte[].
   */
  protected static byte[] decryptBytes(BufferedBlockCipher cipher,
                                       byte[] encBytes)
  {
    try {
      int inLen = encBytes.length;
      return processBytesFully(cipher, encBytes, new byte[inLen], inLen);
    } catch(InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Gets the encoding key combined with the given page number.
   */
  protected byte[] getEncodingKey(int pageNumber) {
    return applyPageNumber(getEncodingKey(), 0, pageNumber);
  }

  /**
   * Reads and returns the header page (page 0) from the given pageChannel.
   */
  protected static ByteBuffer readHeaderPage(PageChannel pageChannel)
    throws IOException
  {
    ByteBuffer buffer = pageChannel.createPageBuffer();
    pageChannel.readPage(buffer, 0);
    return buffer;
  }

  /**
   * Returns a copy of the given key with the bytes of the given pageNumber
   * applied at the given offset using XOR.
   */
  public static byte[] applyPageNumber(byte[] key, int offset, int pageNumber) {

    byte[] tmp = ByteUtil.copyOf(key, key.length);
    ByteBuffer bb = wrap(tmp);
    bb.position(offset);
    bb.putInt(pageNumber);

    for(int i = offset; i < (offset + 4); ++i) {
      tmp[i] ^= key[i];
    }

    return tmp;
  }

  /**
   * Hashes the given bytes using the given digest and returns the result.
   */
  public static byte[] hash(Digest digest, byte[] bytes) {
    return hash(digest, bytes, null, 0);
  }

  /**
   * Hashes the given bytes1 and bytes2 using the given digest and returns the
   * result.
   */
  public static byte[] hash(Digest digest, byte[] bytes1, byte[] bytes2) {
    return hash(digest, bytes1, bytes2, 0);
  }

  /**
   * Hashes the given bytes using the given digest and returns the hash fixed
   * to the given length.
   */
  public static byte[] hash(Digest digest, byte[] bytes, int resultLen) {
    return hash(digest, bytes, null, resultLen);
  }

  /**
   * Hashes the given bytes1 and bytes2 using the given digest and returns the
   * hash fixed to the given length.
   */
  public static byte[] hash(Digest digest, byte[] bytes1, byte[] bytes2,
                            int resultLen) {
    digest.reset();

    digest.update(bytes1, 0, bytes1.length);

    if(bytes2 != null) {
      digest.update(bytes2, 0, bytes2.length);
    }

    // Get digest value
    byte[] digestBytes = new byte[digest.getDigestSize()];
    digest.doFinal(digestBytes, 0);

    // adjust to desired length
    if(resultLen > 0) {
      digestBytes = fixToLength(digestBytes, resultLen);
    }

    return digestBytes;
  }

  /**
   * @return a byte array of the given length, truncating or padding the given
   * byte array as necessary.
   */
  public static byte[] fixToLength(byte[] bytes, int len) {
    return fixToLength(bytes, len, 0);
  }

  /**
   * @return a byte array of the given length, truncating or padding the given
   * byte array as necessary using the given padByte.
   */
  public static byte[] fixToLength(byte[] bytes, int len, int padByte) {
    int byteLen = bytes.length;
    if(byteLen != len) {
      bytes = ByteUtil.copyOf(bytes, len);
      if(byteLen < len) {
        Arrays.fill(bytes, byteLen, len, (byte)padByte);
      }
    }
    return bytes;
  }

  /**
   * @return a new ByteBuffer wrapping the given bytes with the appropriate
   *         byte order
   */
  public static ByteBuffer wrap(byte[] bytes) {
    return ByteBuffer.wrap(bytes).order(PageChannel.DEFAULT_BYTE_ORDER);
  }

  /**
   * Fills the given array with the given value and returns it.
   */
  public static byte[] fill(byte[] bytes, int value) {
    Arrays.fill(bytes, (byte)value);
    return bytes;
  }

  /**
   * Processes all the bytes for the given block cipher.
   */
  protected static byte[] processBytesFully(BufferedBlockCipher cipher,
                                            byte[] inArray, byte[] outArray,
                                            int inLen)
    throws InvalidCipherTextException
  {
    int outLen = cipher.processBytes(inArray, 0, inLen, outArray, 0);
    cipher.doFinal(outArray, outLen);
    return outArray;
  }

  /**
   * @return {@code true} if the given bytes are all 0, {@code false}
   *         otherwise
   */
  protected static boolean isBlankKey(byte[] key) {
    for (byte byteVal : key) {
      if (byteVal != 0) {
        return false;
      }
    }
    return true;
  }

  /**
   * Generates the cipher parameters for the given page number.
   */
  protected abstract CipherParameters computeCipherParams(int pageNumber);

}
