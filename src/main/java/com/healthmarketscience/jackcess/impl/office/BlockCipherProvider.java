/*
Copyright (c) 2013 James Ahlborn

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

  @Override
  public final boolean canEncodePartialPage() {
    // for a variety of reasons, it's difficult (or impossible if chaining
    // modes are in use) for block ciphers to encode partial pages.
    return false;
  }

  @Override
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
