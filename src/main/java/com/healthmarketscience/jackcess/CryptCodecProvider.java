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
import com.healthmarketscience.jackcess.impl.CodecProvider;
import com.healthmarketscience.jackcess.impl.CodecHandler;
import com.healthmarketscience.jackcess.impl.PageChannel;
import com.healthmarketscience.jackcess.impl.JetFormat;
import com.healthmarketscience.jackcess.impl.DefaultCodecProvider;
import com.healthmarketscience.jackcess.impl.JetCryptCodecHandler;
import com.healthmarketscience.jackcess.impl.MSISAMCryptCodecHandler;
import com.healthmarketscience.jackcess.impl.OfficeCryptCodecHandler;


/**
 * Implementation of CodecProvider with support for some forms of Microsoft
 * Access and Microsoft Money file encryption.
 * <p/>
 * Note, not all "encrypted" access databases actually require passwords in
 * order to be opened.  Many older forms of access "encryption" ("obfuscation"
 * would be a better term) include the keys within the access file itself.  If
 * required, a password can be provided in one of two ways:
 * <ul>
 * <li>If a {@link PasswordCallback} has been provided (via the constructor or
 *     {@link #setPasswordCallback}), then {@link
 *     PasswordCallback#getPassword} will be invoked to retrieve the necessary
 *     password</li>
 * <li>If no PasswordCallback has been configured, then {@link #getPassword}
 *     will be invoked directly on the CryptCodecProvider (which will return
 *     the password configured via the constructor or {@link
 *     #setPassword})</li>
 * </ul>
 *
 * @author Vladimir Berezniker
 */
public class CryptCodecProvider implements CodecProvider, PasswordCallback
{
  private String _password;
  private PasswordCallback _callback;

  public CryptCodecProvider() {
    this(null, null);
  }

  public CryptCodecProvider(String password) {
    this(password, null);
  }

  public CryptCodecProvider(PasswordCallback callback) {
    this(null, callback);
  }

  private CryptCodecProvider(String password, PasswordCallback callback) {
    _password = password;
    _callback = callback;
  }

  public String getPassword() {
    return _password;
  }

  public CryptCodecProvider setPassword(String newPassword) {
    _password = newPassword;
    return this;
  }

  public PasswordCallback getPasswordCallback() {
    return _callback;
  }

  public CryptCodecProvider setPasswordCallback(PasswordCallback newCallback) {
    _callback = newCallback;
    return this;
  }

  public CodecHandler createHandler(PageChannel channel, Charset charset)
    throws IOException
  {
    // determine from where to retrieve the password
    PasswordCallback callback = getPasswordCallback();
    if(callback == null) {
      callback = this;
    }
    
    JetFormat format = channel.getFormat();
    switch(format.CODEC_TYPE) {
    case NONE:
      // no encoding, all good
      return DefaultCodecProvider.DUMMY_HANDLER;

    case JET:
      return JetCryptCodecHandler.create(channel);

    case MSISAM:
      return MSISAMCryptCodecHandler.create(callback, channel, charset);

    case OFFICE:
      return OfficeCryptCodecHandler.create(callback, channel, charset);

    default:
      throw new RuntimeException("Unknown codec type " + format.CODEC_TYPE);
    }
  }
}
