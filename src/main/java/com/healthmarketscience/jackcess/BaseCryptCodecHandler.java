/*
Copyright (c) 2010 Vladimir Berezniker

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

package com.healthmarketscience.jackcess;


import java.io.IOException;
import java.nio.ByteBuffer;

import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;


/**
 * Base CodecHandler support for RC4 encryption based CodecHandlers.
 *
 * @author Vladimir Berezniker
 */
public abstract class BaseCryptCodecHandler implements CodecHandler
{
  private RC4Engine _engine;

  protected BaseCryptCodecHandler() {
    _engine = new RC4Engine();
  }

  private RC4Engine getEngine()
  {
    if(_engine == null) {
      _engine = new RC4Engine();
    }
    return _engine;
  }

  /**
   * Decodes the page in the given buffer (in place) using RC4 decryption with
   * the given params.
   *
   * @param buffer encoded page buffer
   * @param params RC4 decryption parameters
   */
  protected void decodePage(ByteBuffer buffer, KeyParameter params) {
    RC4Engine engine = getEngine();
    engine.init(false, params);

    byte[] array = buffer.array();
    engine.processBytes(array, 0, array.length, array, 0);
  }

  public ByteBuffer encodePage(ByteBuffer buffer, int pageNumber, 
                               int pageOffset) {
    throw new UnsupportedOperationException(
        "Encryption is currently not supported");
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
   * Returns a copy of the given key withthe bytes of the given pageNumber
   * applied using XOR.
   */
  protected static byte[] applyPageNumber(byte[] key, int pageNumber)
  {
    byte[] tmp = new byte[key.length];
    ByteBuffer.wrap(tmp).order(PageChannel.DEFAULT_BYTE_ORDER) 
      .putInt(pageNumber);

    for(int i = 0; i < 4; ++i) {
      tmp[i] ^= key[i];
    }

    return tmp;
  }

}
