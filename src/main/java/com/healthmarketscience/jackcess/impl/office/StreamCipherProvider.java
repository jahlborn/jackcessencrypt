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

import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.impl.OfficeCryptCodecHandler;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.StreamCipher;

/**
 *
 * @author James Ahlborn
 */
public abstract class StreamCipherProvider extends OfficeCryptCodecHandler
{
  private StreamCipher _cipher;

  protected StreamCipherProvider(PageChannel channel, byte[] encodingKey) 
  {
    super(channel, encodingKey);
  }

  public boolean canDecodeInline() {
    // stream ciphers can decode on top of the input buffer
    return true;
  }

  @Override
  protected StreamCipher getStreamCipher() {
    if(_cipher == null) {
      _cipher = initCipher();
    }
    return _cipher;
  }

  protected StreamCipher initCipher() {
    throw new UnsupportedOperationException();
  }

  @Override
  protected void decodePageImpl(ByteBuffer inPage, ByteBuffer outPage,
                                int pageNumber) 
  {
    streamDecrypt(inPage, pageNumber);
  }

  @Override
  public ByteBuffer encodePageImpl(ByteBuffer buffer, int pageNumber, 
                                   int pageOffset) 
  {
    return streamEncrypt(buffer, pageNumber, pageOffset);
  }

  @Override
  protected void reset() {
    super.reset();
    _cipher = null;
  }
}
