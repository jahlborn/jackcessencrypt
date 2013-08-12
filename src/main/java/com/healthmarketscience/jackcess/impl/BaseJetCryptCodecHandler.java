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

package com.healthmarketscience.jackcess.impl;

import java.nio.ByteBuffer;

import org.bouncycastle.crypto.engines.RC4Engine;


/**
 * Base CodecHandler support for Jet RC4 encryption based CodecHandlers.
 *
 * @author James Ahlborn
 */
public abstract class BaseJetCryptCodecHandler extends BaseCryptCodecHandler
{
  private RC4Engine _engine;

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
  protected final RC4Engine getStreamCipher() {
    if(_engine == null) {
      _engine = new RC4Engine();
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
