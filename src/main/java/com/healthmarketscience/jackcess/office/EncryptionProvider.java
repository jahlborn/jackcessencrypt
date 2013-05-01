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
import java.nio.charset.Charset;

import com.healthmarketscience.jackcess.BaseCryptCodecHandler;
import com.healthmarketscience.jackcess.ByteUtil;
import com.healthmarketscience.jackcess.KeyCache;
import com.healthmarketscience.jackcess.UnsupportedCodecException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author James Ahlborn
 */
public abstract class EncryptionProvider 
{
  static final Charset UNICODE_CHARSET = Charset.forName("UTF-16LE");
  private static final int MAX_PASSWORD_LEN = 255;

  private Digest _digest;
  private StreamCipher _cipher;
  private final KeyCache<byte[]> _keyCache = new KeyCache<byte[]>() {
    @Override protected byte[] computeKey(int pageNumber) {
      return getEncryptionKey(pageNumber);
    }
  };
  private ByteBuffer _tempIntBuf;

  protected EncryptionProvider() 
  {

  }

  public static EncryptionProvider create(ByteBuffer encProvBuf, 
                                          String password)
  {
    // read encoding provider version
    // uint (2.1.4 Version)
    int vMajor = ByteUtil.getUnsignedShort(encProvBuf);
    // uint
    int vMinor = ByteUtil.getUnsignedShort(encProvBuf);

    System.out.println("FOO ver " + vMajor + " " + vMinor);

    byte[] pwdBytes = getPasswordBytes(password);

    EncryptionProvider provider = null;
    if((vMajor == 4) && (vMinor == 4)) {
      // OC: 2.3.4.10 - Agile Encryption: 4,4
      // FIXME

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
          provider = new RC4CryptoAPIProvider(encProvBuf, pwdBytes);
        }
      }
    }

    if(provider == null) {
      throw new UnsupportedCodecException(
          "Unsupported office encryption provider: vMajor " + vMajor + 
          ", vMinor " + vMinor);
    }
    
    if(!provider.verifyPassword(password)) {
      throw new IllegalStateException("Incorrect password provided");
    }

    return provider;
  }

  protected Digest getDigest() {
    if(_digest == null) {
      _digest = initDigest();
    }
    return _digest;
  }

  protected Digest initDigest() {
    throw new UnsupportedOperationException();
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

  protected byte[] int2bytes(int val) {
    if(_tempIntBuf == null) {
      _tempIntBuf = BaseCryptCodecHandler.wrap(new byte[4]);
    }
    _tempIntBuf.putInt(0, val);
    return _tempIntBuf.array();
  }

  public void decodePage(ByteBuffer buffer, int pageNumber) 
  {
    System.out.println("FOO decoding page " + pageNumber);

    System.out.println("FOO enc page\n" + ByteUtil.toHexString(buffer, 0, 200));

    StreamCipher cipher = getCipher();
    cipher.init(BaseCryptCodecHandler.CIPHER_DECRYPT_MODE, 
                new KeyParameter(_keyCache.get(pageNumber)));

    byte[] array = buffer.array();
    cipher.processBytes(array, 0, array.length, array, 0);

    System.out.println("FOO dec page\n" + ByteUtil.toHexString(buffer, 0, 200));


    // FIXME test alternate decode strategies
    // for(int i = 0; i < 10; ++i) {

    //   StreamCipher cipher = getCipher();
    //   cipher.init(BaseCryptCodecHandler.CIPHER_DECRYPT_MODE, 
    //               new KeyParameter(_keyCache.get(i)));

    //   // try "RC4-drop[n]" approach
    //   for(int j = 0; j < 4096; ++j) {

    //     // drop part of key stream
    //     for(int k = 0; k < j; ++k) {
    //       cipher.returnByte((byte)0);
    //     }

    //     // byte[] array = buffer.array();
    //     // cipher.processBytes(array, 0, array.length, array, 0);

    //     byte[] array = buffer.array();
    //     byte[] outArr = new byte[4096];
    //     cipher.processBytes(array, 0, array.length, outArr, 0);

    //     // System.out.println("FOO dec page " + i + "\n" + ByteUtil.toHexString(ByteBuffer.wrap(outArr), 0, 200));

    //     if((outArr[0] == 0x01) && (outArr[1] == 0x01) && (outArr[2] == 0x64)) {
    //       System.out.println("FOO SUCCESS dec page " + i + " drop[" + j + "]\n" + ByteUtil.toHexString(ByteBuffer.wrap(outArr), 0, 200));
    //     }
    //   }
    // }
  }

  public void encodePage(ByteBuffer buffer, ByteBuffer encodeBuf,
                         int pageNumber) 
  {
    StreamCipher cipher = getCipher();
    cipher.init(BaseCryptCodecHandler.CIPHER_ENCRYPT_MODE, 
                new KeyParameter(_keyCache.get(pageNumber)));

    byte[] inArray = buffer.array();
    cipher.processBytes(inArray, 0, inArray.length, encodeBuf.array(), 0);
  }

  @Override
  public String toString() {
    return getClass().getSimpleName();
  }

  protected static EncryptionHeader readEncryptionHeader(ByteBuffer encProvBuf)
  {
    // read length of header
    int headerLen = encProvBuf.getInt();

    // read header (temporarily narrowing buf to header)
    int curLimit = encProvBuf.limit();
    int curPos = encProvBuf.position();
    encProvBuf.limit(curPos + headerLen);
    EncryptionHeader header = new EncryptionHeader(encProvBuf);
    
    // move to after header
    encProvBuf.limit(curLimit);
    encProvBuf.position(curPos + headerLen);

    return header;
  }

  protected byte[] iterateHash(byte[] baseHash, int iterations) {
    Digest digest = getDigest();
    byte[] iterHash = baseHash;
    for(int i = 0; i < iterations; ++i) {
      iterHash = BaseCryptCodecHandler.hash(digest, int2bytes(i), iterHash);
    }
    return iterHash;
  }

  private static byte[] getPasswordBytes(String password)
  {
    if(password.length() > MAX_PASSWORD_LEN) {
      password = password.substring(0, MAX_PASSWORD_LEN);
    } 

    return password.getBytes(UNICODE_CHARSET);
  }

  protected abstract boolean verifyPassword(String password);

  protected abstract byte[] getEncryptionKey(int pageNumber);

}
