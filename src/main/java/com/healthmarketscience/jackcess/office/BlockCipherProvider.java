/*
Copyright (c) 2013 James Ahlborn

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307
USA
*/

package com.healthmarketscience.jackcess.office;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import com.healthmarketscience.jackcess.OfficeCryptCodecHandler;
import com.healthmarketscience.jackcess.PageChannel;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 *
 * @author James Ahlborn
 */
public abstract class BlockCipherProvider extends OfficeCryptCodecHandler 
{
  private BufferedBlockCipher _cipher;

  public BlockCipherProvider(PageChannel channel, byte[] encodingKey) 
  {
    super(channel, encodingKey);
  }

  protected BufferedBlockCipher getCipher() {
    if(_cipher == null) {
      _cipher = new 
        PaddedBufferedBlockCipher(initCipher(), new ZeroBytePadding());
    }
    return _cipher;
  }

  protected BlockCipher initCipher() {
    switch(getPhase()) {
    case PWD_VERIFY:
      return initPwdCipher();
    case CRYPT:
      return initCryptCipher();
    default:
      throw new RuntimeException("unknown phase " + getPhase());
    }
  }

  protected BlockCipher initPwdCipher() {
    throw new UnsupportedOperationException();
  }

  protected BlockCipher initCryptCipher() {
    throw new UnsupportedOperationException();
  }

  @Override
  protected void decodePageImpl(ByteBuffer buffer, int pageNumber) 
  {
    BufferedBlockCipher cipher = getCipher();
    cipher.init(CIPHER_DECRYPT_MODE, getEncryptionKey(pageNumber));

    try {      
      // we can't encode inline, so copy encoded data to temp buf before
      // decoding
      byte[] outArray = buffer.array();
      int inLen = outArray.length;
      byte[] inArray = getTempEncodeBuffer().array();
      System.arraycopy(outArray, 0, inArray, 0, inLen);
      processBytesFully(cipher, inArray, fill(outArray, 0), inLen);
    } catch(InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  public void encodePageImpl(ByteBuffer buffer, ByteBuffer encodeBuf,
                             int pageNumber) 
    throws IOException
  {
    BufferedBlockCipher cipher = getCipher();
    cipher.init(CIPHER_ENCRYPT_MODE, getEncryptionKey(pageNumber));

    try {
      byte[] inArray = buffer.array();
      int inLen = inArray.length;
      processBytesFully(cipher, inArray, fill(encodeBuf.array(), 0), inLen);
    } catch(InvalidCipherTextException e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  protected void reset() {
    super.reset();
    _cipher = null;
  }

  protected byte[] decryptBytes(byte[] keyBytes, byte[] iv, byte[] encBytes) {
    BufferedBlockCipher cipher = getCipher();
    cipher.init(CIPHER_DECRYPT_MODE, 
                new ParametersWithIV(new KeyParameter(keyBytes), iv));
    return decryptBytes(cipher, encBytes);
  }

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

  private static byte[] processBytesFully(BufferedBlockCipher cipher,
                                          byte[] inArray, byte[] outArray,
                                          int inLen)
    throws InvalidCipherTextException
  {
    int outLen = cipher.processBytes(inArray, 0, inLen, outArray, 0);
    cipher.doFinal(outArray, outLen);
    return outArray;
  }
}
