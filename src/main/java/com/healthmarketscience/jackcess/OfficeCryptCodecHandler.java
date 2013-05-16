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

import com.healthmarketscience.jackcess.office.AgileEncryptionProvider;
import com.healthmarketscience.jackcess.office.EncryptionHeader;
import com.healthmarketscience.jackcess.office.RC4CryptoAPIProvider;
import org.bouncycastle.crypto.CipherParameters;
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

  private final byte[] _encodingKey;
  private Digest _digest;
  private ByteBuffer _tempIntBuf;
  private final KeyCache<CipherParameters> _keyCache = 
    new KeyCache<CipherParameters>() {
      @Override protected CipherParameters computeKey(int pageNumber) {
        return computeEncryptionKey(pageNumber);
      }
    };
  private Phase _phase = Phase.PWD_VERIFY;

  protected OfficeCryptCodecHandler(PageChannel channel, byte[] encodingKey) 
  {
    super(channel);
    _encodingKey = encodingKey;
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

    if(isBlankKey(encodingKey)) {
      return DefaultCodecProvider.DUMMY_HANDLER;
    }

    System.out.println("FOO creating office handler");

    System.out.println("FOO header\n" + ByteUtil.toHexString(buffer, 0, 0xa0));

    short infoLen = buffer.getShort(CRYPT_STRUCTURE_OFFSET);
    System.out.println("FOO info len " + infoLen);

    ByteBuffer encProvBuf = 
      wrap(ByteUtil.getBytes(buffer, CRYPT_STRUCTURE_OFFSET + 2, infoLen));
    
    System.out.println("FOO info: " + ByteUtil.toHexString(encProvBuf, 0, encProvBuf.remaining()));


    // read encoding provider version
    // uint (2.1.4 Version)
    int vMajor = ByteUtil.getUnsignedShort(encProvBuf);
    // uint
    int vMinor = ByteUtil.getUnsignedShort(encProvBuf);

    System.out.println("FOO ver " + vMajor + " " + vMinor);

    byte[] pwdBytes = getPasswordBytes(password);

    OfficeCryptCodecHandler handler = null;
    if((vMajor == 4) && (vMinor == 4)) {
      // OC: 2.3.4.10 - Agile Encryption: 4,4
      handler = new AgileEncryptionProvider(channel, encodingKey, encProvBuf, 
                                            pwdBytes);

    } else if((vMajor == 1) && (vMinor == 1)) {
      // OC: 2.3.6.1 - RC4 Encryption: 1,1
      // FIXME

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
          // FIXME

        } else {
          // OC: 2.3.5.1 - RC4 CryptoAPI Encryption: (2,3,4),2
          handler = new RC4CryptoAPIProvider(channel, encodingKey, encProvBuf,
                                             pwdBytes);
        }
      }
    }

    if(handler == null) {
      throw new UnsupportedCodecException(
          "Unsupported office encryption provider: vMajor " + vMajor + 
          ", vMinor " + vMinor);
    }
    
    if(!handler.verifyPassword(pwdBytes)) {
      throw new IllegalStateException("Incorrect password provided");
    }

    handler.reset();
    handler._phase = Phase.CRYPT;

    return handler;
  }

  protected Phase getPhase() {
    return _phase;
  }

  protected byte[] getEncodingKey() {
    return _encodingKey;
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

  protected CipherParameters getEncryptionKey(int pageNumber)
  {
    return _keyCache.get(pageNumber);
  }

  protected final byte[] int2bytes(int val) {
    if(_tempIntBuf == null) {
      _tempIntBuf = wrap(new byte[4]);
    }
    _tempIntBuf.putInt(0, val);
    return _tempIntBuf.array();
  }

  // public boolean canEncodePartialPage() {
  //   // FIXME, this will probably depend on the algo
  //   return false;
  // }
  
  protected void reset() {
    _digest = null;
  }

  public void decodePage(ByteBuffer buffer, int pageNumber) 
    throws IOException
  {
    if(!isEncryptedPage(pageNumber)) {
      // not encoded
      return;
    }

    decodePageImpl(buffer, pageNumber);
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

    ByteBuffer encodeBuf = getTempEncodeBuffer();
    encodePageImpl(buffer, encodeBuf, pageNumber);
    return encodeBuf;
  }

  protected byte[] iterateHash(byte[] baseHash, int iterations) {
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
    if(password.length() > MAX_PASSWORD_LEN) {
      password = password.substring(0, MAX_PASSWORD_LEN);
    } 

    return password.getBytes(EncryptionHeader.UNICODE_CHARSET);
  }

  protected static int bits2bytes(int bits) {
    return bits/8;
  }

  protected abstract void decodePageImpl(ByteBuffer buffer, int pageNumber)
    throws IOException;

  protected abstract void encodePageImpl(ByteBuffer buffer, 
                                         ByteBuffer encodeBuf, int pageNumber)
    throws IOException;

  protected abstract boolean verifyPassword(byte[] pwdBytes);

  protected abstract CipherParameters computeEncryptionKey(int pageNumber);
}
