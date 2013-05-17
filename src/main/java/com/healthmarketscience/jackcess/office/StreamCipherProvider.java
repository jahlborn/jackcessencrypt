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

import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.OfficeCryptCodecHandler;
import com.healthmarketscience.jackcess.PageChannel;
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

  protected StreamCipher getCipher() {
    if(_cipher == null) {
      _cipher = initCipher();
    }
    return _cipher;
  }

  protected StreamCipher initCipher() {
    throw new UnsupportedOperationException();
  }

  @Override
  protected void decodePageImpl(ByteBuffer buffer, int pageNumber) 
  {
    StreamCipher cipher = getCipher();
    cipher.init(CIPHER_DECRYPT_MODE, getEncryptionKey(pageNumber));

    byte[] array = buffer.array();
    cipher.processBytes(array, 0, array.length, array, 0);
  }

  @Override
  public void encodePageImpl(ByteBuffer buffer, ByteBuffer encodeBuf,
                             int pageNumber) 
  {
    StreamCipher cipher = getCipher();
    cipher.init(CIPHER_ENCRYPT_MODE, getEncryptionKey(pageNumber));

    byte[] inArray = buffer.array();
    cipher.processBytes(inArray, 0, inArray.length, encodeBuf.array(), 0);
  }

  @Override
  protected void reset() {
    super.reset();
    _cipher = null;
  }

  protected static byte[] decryptBytes(StreamCipher cipher, byte[] encBytes)
  {
    byte[] bytes = new byte[encBytes.length];
    cipher.processBytes(encBytes, 0, encBytes.length, bytes, 0);
    return bytes;
  }
}
