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

package com.healthmarketscience.jackcess.impl;

import java.io.IOException;
import java.nio.ByteBuffer;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * CodecHandler for Jet databases.
 *
 * @author Vladimir Berezniker
 */
public class JetCryptCodecHandler extends BaseJetCryptCodecHandler 
{
  final static int ENCODING_KEY_LENGTH = 0x4;

  JetCryptCodecHandler(PageChannel channel, byte[] encodingKey) {
    super(channel, encodingKey);
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

  @Override
  protected KeyParameter computeCipherParams(int pageNumber) {
    return new KeyParameter(getEncodingKey(pageNumber));
  }

  @Override
  protected int getMaxEncodedPage() {
    return Integer.MAX_VALUE;
  }

}
