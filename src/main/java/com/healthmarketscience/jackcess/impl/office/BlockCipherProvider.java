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

package com.healthmarketscience.jackcess.impl.office;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.impl.OfficeCryptCodecHandler;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;

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
      _cipher = new BufferedBlockCipher(initCipher());
    }
    return _cipher;
  }

  public final boolean canEncodePartialPage() {
    // for a variety of reasons, it's difficult (or impossible if chaining
    // modes are in use) for block ciphers to encode partial pages.
    return false;
  }

  public final boolean canDecodeInline() {
    // block ciphers cannot decode on top of the input buffer
    return false;
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
  protected void decodePageImpl(ByteBuffer inPage, ByteBuffer outPage,
                                int pageNumber) 
  {
    blockDecrypt(inPage, outPage, pageNumber);
  }

  @Override
  public ByteBuffer encodePageImpl(ByteBuffer buffer, int pageNumber, 
                                   int pageOffset) 
    throws IOException
  {
    return blockEncrypt(buffer, pageNumber);
  }

  @Override
  protected void reset() {
    super.reset();
    _cipher = null;
  }
}
