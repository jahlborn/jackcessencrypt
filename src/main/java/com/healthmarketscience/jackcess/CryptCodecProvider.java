/*
Copyright (c) 2010 Vladimir Berezniker

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
 * <p>
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

  @Override
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

  @Override
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
