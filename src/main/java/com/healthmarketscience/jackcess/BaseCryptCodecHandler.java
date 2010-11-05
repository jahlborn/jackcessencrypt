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
 *
 * @author Vladimir Berezniker
 */
public abstract class BaseCryptCodecHandler implements CodecHandler
{
  private final ByteBuffer _pageNumberBuf;
  private final RC4Engine _engine;

  protected BaseCryptCodecHandler(PageChannel channel) {
    _pageNumberBuf = channel.createBuffer(4);
    _engine = new RC4Engine();
  }

  protected void decodePage(ByteBuffer buffer, KeyParameter params) {
      _engine.init(false, params);

      byte[] array = buffer.array();
      _engine.processBytes(array, 0, array.length, array, 0);
  }

  public ByteBuffer encodePage(ByteBuffer buffer, int pageNumber, 
                               int pageOffset) {
    throw new UnsupportedOperationException(
        "Encryption is currently not supported");
  }

  protected static ByteBuffer readHeaderPage(PageChannel pageChannel)
    throws IOException
  {
    ByteBuffer buffer = pageChannel.createPageBuffer();
    pageChannel.readPage(buffer, 0);
    return buffer;
  }

  protected void applyPageNumber(byte[] key, int pageNumber)
  {
    _pageNumberBuf.clear();
    _pageNumberBuf.putInt(pageNumber);

    for(int i = 0; i < 4; ++i) {
      key[i] ^= _pageNumberBuf.get(i);
    }
  }
}
