/*
Copyright (c) 2013 James Ahlborn

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

package com.healthmarketscience.jackcess.crypt.impl;

import com.healthmarketscience.jackcess.crypt.InvalidCredentialsException;
import com.healthmarketscience.jackcess.crypt.InvalidCryptoConfigurationException;
import com.healthmarketscience.jackcess.crypt.impl.office.AgileEncryptionProvider;
import com.healthmarketscience.jackcess.crypt.impl.office.ECMAStandardEncryptionProvider;
import com.healthmarketscience.jackcess.crypt.impl.office.EncryptionHeader;
import com.healthmarketscience.jackcess.crypt.impl.office.NonStandardEncryptionProvider;
import com.healthmarketscience.jackcess.crypt.impl.office.OfficeBinaryDocRC4Provider;
import com.healthmarketscience.jackcess.crypt.impl.office.RC4CryptoAPIProvider;
import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.CodecHandler;
import com.healthmarketscience.jackcess.impl.DefaultCodecProvider;
import com.healthmarketscience.jackcess.impl.JetFormat;
import com.healthmarketscience.jackcess.impl.PageChannel;
import com.healthmarketscience.jackcess.impl.UnsupportedCodecException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.function.Supplier;
import org.bouncycastle.crypto.Digest;

/**
 * CryptCodecHandler for the  Office Document Cryptography standard.
 *
 * @author James Ahlborn
 */
public abstract class OfficeCryptCodecHandler extends BaseCryptCodecHandler
{
  private static final int MAX_PASSWORD_LEN = 255;
  private static final int CRYPT_STRUCTURE_OFFSET = 0x299;

  protected enum Phase { PWD_VERIFY, CRYPT; }

  private Digest _digest;
  private ByteBuffer _tempIntBuf;
  private Phase _phase = Phase.PWD_VERIFY;

  protected OfficeCryptCodecHandler(PageChannel channel, byte[] encodingKey)
  {
    super(channel, encodingKey);
  }

  public static CodecHandler create(Supplier<String> callback, PageChannel channel,
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

    if(isBlankKey(encodingKey)) {
      return DefaultCodecProvider.DUMMY_HANDLER;
    }

    short infoLen = buffer.getShort(CRYPT_STRUCTURE_OFFSET);

    ByteBuffer encProvBuf =
      wrap(ByteUtil.getBytes(buffer, CRYPT_STRUCTURE_OFFSET + 2, infoLen));

    // read encoding provider version
    // uint (2.1.4 Version)
    int vMajor = ByteUtil.getUnsignedShort(encProvBuf);
    // uint
    int vMinor = ByteUtil.getUnsignedShort(encProvBuf);

    byte[] pwdBytes = getPasswordBytes(callback.get());

    OfficeCryptCodecHandler handler = null;
    if((vMajor == 4) && (vMinor == 4)) {

      // OC: 2.3.4.10 - Agile Encryption: 4,4
      handler = new AgileEncryptionProvider(channel, encodingKey, encProvBuf,
                                            pwdBytes);

    } else if((vMajor == 1) && (vMinor == 1)) {

      // OC: 2.3.6.1 - RC4 Encryption: 1,1
      handler = new OfficeBinaryDocRC4Provider(channel, encodingKey, encProvBuf,
                                               pwdBytes);

    } else if(((vMajor == 3) || (vMajor == 4)) &&
              (vMinor == 3)) {

      // OC: 2.3.4.6 - Extensible Encryption: (3,4),3

      // since this utilizes arbitrary external providers, we can't really
      // do anything with it
      throw new UnsupportedCodecException(
          "Extensible encryption provider is not supported");

    } else if(((vMajor == 2) || (vMajor == 3) || (vMajor == 4)) &&
              (vMinor == 2)) {

      // read flags (copy of the flags in EncryptionHeader)
      int flags = encProvBuf.getInt();
      if(EncryptionHeader.isFlagSet(
             flags, EncryptionHeader.FCRYPTO_API_FLAG)) {
        if(EncryptionHeader.isFlagSet(flags, EncryptionHeader.FAES_FLAG)) {
          // OC: 2.3.4.5 - Standard Encryption: (3,4),2
          handler = new ECMAStandardEncryptionProvider(channel, encodingKey,
                                                       encProvBuf, pwdBytes);
        } else {

          int initPos = encProvBuf.position();
          try {

            // OC: 2.3.5.1 - RC4 CryptoAPI Encryption: (2,3,4),2
            handler = new RC4CryptoAPIProvider(channel, encodingKey, encProvBuf,
                                               pwdBytes);

          } catch(InvalidCryptoConfigurationException icce) {

            // is this the "non-standard" encryption provider?
            try {
              // reset encryption info buf before attempting to re-process
              encProvBuf.position(initPos);
              handler = new NonStandardEncryptionProvider(channel, encodingKey,
                                                          encProvBuf, pwdBytes);
            } catch(Exception ignored) {
              // ignore nested exception, continue with original
              throw icce;
            }
          }
        }
      }
    }

    if(handler == null) {
      throw new UnsupportedCodecException(
          "Unsupported office encryption provider: vMajor " + vMajor +
          ", vMinor " + vMinor);
    }

    if(!handler.verifyPassword(pwdBytes)) {
      throw new InvalidCredentialsException("Incorrect password provided");
    }

    handler.reset();
    handler._phase = Phase.CRYPT;

    return handler;
  }

  protected Phase getPhase() {
    return _phase;
  }

  protected Digest getDigest() {
    if(_digest == null) {
      _digest = initDigest();
    }
    return _digest;
  }

  protected Digest initDigest() {
    switch(getPhase()) {
    case PWD_VERIFY:
      return initPwdDigest();
    case CRYPT:
      return initCryptDigest();
    default:
      throw new RuntimeException("unknown phase " + getPhase());
    }
  }

  protected Digest initPwdDigest() {
    throw new UnsupportedOperationException();
  }

  protected Digest initCryptDigest() {
    throw new UnsupportedOperationException();
  }

  protected final byte[] int2bytes(int val) {
    if(_tempIntBuf == null) {
      _tempIntBuf = wrap(new byte[4]);
    }
    _tempIntBuf.putInt(0, val);
    return _tempIntBuf.array();
  }

  protected void reset() {
    _digest = null;
  }

  @Override
  public void decodePage(ByteBuffer inPage, ByteBuffer outPage, int pageNumber)
    throws IOException
  {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return;
    }

    decodePageImpl(inPage, outPage, pageNumber);
  }

  @Override
  public ByteBuffer encodePage(ByteBuffer buffer, int pageNumber,
                               int pageOffset)
    throws IOException
  {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return buffer;
    }

    return encodePageImpl(buffer, pageNumber, pageOffset);
  }

  protected byte[] iterateHash(byte[] baseHash, int iterations) {

    if(iterations == 0) {
      return baseHash;
    }

    Digest digest = getDigest();
    byte[] iterHash = baseHash;
    for(int i = 0; i < iterations; ++i) {
      iterHash = hash(digest, int2bytes(i), iterHash);
    }
    return iterHash;
  }

  private static boolean isEncryptedPage(int pageNumber) {
    return (pageNumber > 0);
  }

  private static byte[] getPasswordBytes(String password) {
    if(password == null) {
      return new byte[0];
    }
    if(password.length() > MAX_PASSWORD_LEN) {
      password = password.substring(0, MAX_PASSWORD_LEN);
    }

    return password.getBytes(EncryptionHeader.UNICODE_CHARSET);
  }

  protected static int bits2bytes(int bits) {
    return bits/8;
  }

  protected abstract void decodePageImpl(ByteBuffer inPage, ByteBuffer outPage,
                                         int pageNumber)
    throws IOException;

  protected abstract ByteBuffer encodePageImpl(
      ByteBuffer buffer, int pageNumber, int pageOffset)
    throws IOException;

  protected abstract boolean verifyPassword(byte[] pwdBytes);
}
