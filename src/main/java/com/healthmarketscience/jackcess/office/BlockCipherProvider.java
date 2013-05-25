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

  @Override
  protected BufferedBlockCipher getBlockCipher() {
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
    blockDecrypt(buffer, pageNumber);
  }

  @Override
  public ByteBuffer encodePageImpl(ByteBuffer buffer, int pageNumber, 
                                   int pageOffset) 
    throws IOException
  {
    return blockEncrypt(buffer, pageNumber, pageOffset);
  }

  @Override
  protected void reset() {
    super.reset();
    _cipher = null;
  }

  protected byte[] decryptBytes(byte[] keyBytes, byte[] iv, byte[] encBytes) {
    BufferedBlockCipher cipher = decryptInit(
        getBlockCipher(), new ParametersWithIV(new KeyParameter(keyBytes), iv));
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
}
