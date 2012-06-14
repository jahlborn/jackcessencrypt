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
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * CodecHandler for Jet databases.
 *
 * @author Vladimir Berezniker
 */
public class JetCryptCodecHandler extends BaseCryptCodecHandler 
{
  final static int ENCODING_KEY_LENGTH = 0x4;

  private final byte[] _encodingKey;

  JetCryptCodecHandler(PageChannel channel, byte[] encodingKey) {
    super(channel);
    _encodingKey = encodingKey;
  }

  public static CodecHandler create(PageChannel channel)
    throws IOException
  {
    ByteBuffer buffer = readHeaderPage(channel);
    JetFormat format = channel.getFormat();

    byte[] encodingKey = ByteUtil.getBytes(buffer, format.OFFSET_ENCODING_KEY, 
                                           ENCODING_KEY_LENGTH);

    return (isBlankKey(encodingKey) ? DefaultCodecProvider.DUMMY_HANDLER :
            new JetCryptCodecHandler(channel, encodingKey));
  }

  public boolean canEncodePartialPage() {
    // RC4 ciphers are not influenced by the page contents, so we can easily
    // encode part of the buffer.
    return true;
  }

  public void decodePage(ByteBuffer buffer, int pageNumber) {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return;
    }

    byte[] key = applyPageNumber(_encodingKey, 0, pageNumber);
    decodePage(buffer, new KeyParameter(key));
  }

  @Override
  public ByteBuffer encodePage(ByteBuffer buffer, int pageNumber, 
                               int pageOffset) {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return buffer;
    }

    byte[] key = applyPageNumber(_encodingKey, 0, pageNumber);
    return encodePage(buffer, pageOffset, new KeyParameter(key));
  }

  protected int getMaxEncodedPage()
  {
    return Integer.MAX_VALUE;
  }

  private boolean isEncryptedPage(int pageNumber) {
    return ((pageNumber > 0) && (pageNumber <= getMaxEncodedPage()));
  }

}
