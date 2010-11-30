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
import java.nio.charset.Charset;

/**
 * Implementation of CodecProvider with support for some forms of Microsoft
 * Access and Microsoft Money file encryption.
 *
 * @author Vladimir Berezniker
 */
public class CryptCodecProvider implements CodecProvider
{
  private String _password;

  public CryptCodecProvider() {
    this(null);
  }

  public CryptCodecProvider(String password) {
    _password = password;
  }

  public String getPassword() 
  {
    return _password;
  }

  public void setPassword(String newPassword) 
  {
    _password = newPassword;
  }

  public CodecHandler createHandler(PageChannel channel, Charset charset)
    throws IOException
  {
    JetFormat format = channel.getFormat();
    switch(format.CODEC_TYPE) {
    case NONE:
      // no encoding, all good
      return DefaultCodecProvider.DUMMY_HANDLER;

    case JET:
      return JetCryptCodecHandler.create(channel);

    case MSISAM:
      return MSISAMCryptCodecHandler.create(getPassword(), channel, charset);

    default:
      throw new RuntimeException("Unknown codec type " + format.CODEC_TYPE);
    }
  }

}
