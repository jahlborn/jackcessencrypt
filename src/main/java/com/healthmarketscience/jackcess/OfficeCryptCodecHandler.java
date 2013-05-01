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

package com.healthmarketscience.jackcess;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

import com.healthmarketscience.jackcess.office.EncryptionProvider;

/**
 * CryptCodecHandler for the  Office Document Cryptography standard.
 *
 * @author James Ahlborn
 */
public class OfficeCryptCodecHandler extends BaseCryptCodecHandler 
{
  private static final int CRYPT_STRUCTURE_OFFSET = 0x299;

  private final EncryptionProvider _provider;

  private OfficeCryptCodecHandler(PageChannel channel, String password, 
                                  Charset charset, ByteBuffer buffer) 
  {
    super(channel);

    System.out.println("FOO creating office handler");

    JetFormat format = channel.getFormat();
    System.out.println("FOO pwd mask " + ByteUtil.toHexString(
                           Database.getPasswordMask(buffer, format)));

    System.out.println("FOO header\n" + ByteUtil.toHexString(buffer, 0, 0xa0));

    short infoLen = buffer.getShort(CRYPT_STRUCTURE_OFFSET);
    System.out.println("FOO info len " + infoLen);

    ByteBuffer encProvBuf = 
      wrap(ByteUtil.getBytes(buffer, CRYPT_STRUCTURE_OFFSET + 2, infoLen));
    
    System.out.println("FOO info: " + ByteUtil.toHexString(encProvBuf, 0, encProvBuf.remaining()));

    _provider = EncryptionProvider.create(encProvBuf, password);
  }

  public static CodecHandler create(String password, PageChannel channel,
                                    Charset charset)
    throws IOException
  {
    ByteBuffer buffer = readHeaderPage(channel);
    JetFormat format = channel.getFormat();

    // the encoding key indicates whether or not the db is encoded (but is
    // otherwise meaningless?)
    byte[] encodingKey = ByteUtil.getBytes(
        buffer, format.OFFSET_ENCODING_KEY,
        JetCryptCodecHandler.ENCODING_KEY_LENGTH);

    return (isBlankKey(encodingKey) ? DefaultCodecProvider.DUMMY_HANDLER :
            new OfficeCryptCodecHandler(channel, password, charset, buffer));
  }

  public boolean canEncodePartialPage() {
    // FIXME, this will probably depend on the algo
    return false;
  }

  public void decodePage(ByteBuffer buffer, int pageNumber) {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return;
    }

    _provider.decodePage(buffer, pageNumber);
  }

  public ByteBuffer encodePage(ByteBuffer buffer, int pageNumber, 
                               int pageOffset) {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return buffer;
    }

    ByteBuffer encodeBuf = getTempEncodeBuffer();
    _provider.encodePage(buffer, encodeBuf, pageNumber);
    return encodeBuf;
  }

  private boolean isEncryptedPage(int pageNumber) {
    return (pageNumber > 0);
  }


}
