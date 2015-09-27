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

package com.healthmarketscience.jackcess.impl;

import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.util.StreamCipherCompat;
import com.healthmarketscience.jackcess.util.StreamCipherFactory;


/**
 * Base CodecHandler support for Jet RC4 encryption based CodecHandlers.
 *
 * @author James Ahlborn
 */
public abstract class BaseJetCryptCodecHandler extends BaseCryptCodecHandler
{
  private StreamCipherCompat _engine;

  protected BaseJetCryptCodecHandler(PageChannel channel, byte[] encodingKey) {
    super(channel, encodingKey);
  }

  public boolean canEncodePartialPage() {
    // RC4 ciphers are not influenced by the page contents, so we can easily
    // encode part of the buffer.
    return true;
  }

  public boolean canDecodeInline() {
    // RC4 ciphers can decode on top of the input buffer
    return true;
  }

  @Override
  protected final StreamCipherCompat getStreamCipher() {
    if(_engine == null) {
      _engine = StreamCipherFactory.newRC4Engine();
    }
    return _engine;
  }

  public void decodePage(ByteBuffer inPage, ByteBuffer outPage, int pageNumber) {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return;
    }

    streamDecrypt(inPage, pageNumber);
  }

  public ByteBuffer encodePage(ByteBuffer buffer, int pageNumber, 
                               int pageOffset) {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return buffer;
    }

    return streamEncrypt(buffer, pageNumber, pageOffset);
  }

  private boolean isEncryptedPage(int pageNumber) {
    return ((pageNumber > 0) && (pageNumber <= getMaxEncodedPage()));
  }

  protected abstract int getMaxEncodedPage();
}
