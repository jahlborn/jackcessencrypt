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
import java.nio.charset.Charset;
import java.util.Arrays;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author Vladimir Berezniker
 */
public class MSISAMCryptCodecHandler extends BaseCryptCodecHandler
{
  private final static int SALT_OFFSET = 0x72;
  private final static int CRYPT_CHECK_START = 0x2e9;
  private final static int ENCRYPTION_FLAGS_OFFSET = 0x298;
  private final static int SALT_LENGTH = 0x4;
  private final static int PASSWORD_LENGTH = 0x28;
  private final static int USE_SHA1 = 0x20;
  private final static int PASSWORD_DIGEST_LENGTH = 0x10;
  private final static int MSISAM_MAX_ENCRYPTED_PAGE = 0xE;

  private final byte[] _pwdDigest;
  private final byte[] _baseSalt;

  private final byte[] _salt1;
  private final byte[] _salt2;

  public MSISAMCryptCodecHandler(String password, PageChannel channel, 
                                 Charset charset) 
    throws IOException
  {
    super(channel);
    ByteBuffer buffer = readHeaderPage(channel);

//     // FIXME temp hack
//     byte[] header = new byte[0x98];
//     buffer.position(0);
//     buffer.get(header);

//     System.out.println("FOO db header: \n" + ByteUtil.toHexString(header));
    
    byte[] encrypted4BytesCheck = new byte[4];
    byte[] salt = new byte[8];
      
    int cryptCheckOffset = ByteUtil.getUnsignedByte(buffer, SALT_OFFSET);
    buffer.position(CRYPT_CHECK_START + cryptCheckOffset);
    buffer.get(encrypted4BytesCheck);

    buffer.position(SALT_OFFSET);
    buffer.get(salt);

    _pwdDigest = createPasswordDigest(buffer, password, charset);

    _baseSalt = Arrays.copyOf(salt, SALT_LENGTH);

    RC4Engine rc4e = new RC4Engine();
    rc4e.init(false, new KeyParameter(concat(_pwdDigest, salt)));

//     System.out.println("FOO encrypted bytes " + ByteUtil.toHexString(encrypted4BytesCheck));
    
    byte[] decrypted4BytesCheck = new byte[4];
    rc4e.processBytes(encrypted4BytesCheck, 0,
                      encrypted4BytesCheck.length, decrypted4BytesCheck, 0);

    if (!Arrays.equals(decrypted4BytesCheck, _baseSalt)) {
      throw new IllegalStateException(
          String.format(
              "Decrypted bytes are %s but they should have been %s",
              ByteUtil.toHexString(decrypted4BytesCheck),
              ByteUtil.toHexString(_baseSalt)));
    }
//     System.out.println("FOO password passed");

    _salt1 = new byte[4];
    _salt2 = new byte[4];

    buffer.position(SALT_OFFSET);
    buffer.get(_salt1);
    buffer.get(_salt2);

  }

  public void decodePage(ByteBuffer buffer, int pageNumber) {
    if((pageNumber == 0) || (pageNumber > MSISAM_MAX_ENCRYPTED_PAGE)) {
      // not encoded
      return;
    }

    byte[] salt = ByteUtil.copyOf(_baseSalt, _baseSalt.length);
    applyPageNumber(salt, pageNumber);

    byte[] key = concat(_pwdDigest, salt);
    
    decodePage(buffer, new KeyParameter(key));
  }

  private static byte[] createPasswordDigest(
      ByteBuffer buffer, String password, Charset charset)
  {
      Digest digest;
//       System.out.println("FOO encrypt flags " + buffer.get(ENCRYPTION_FLAGS_OFFSET));
      if ((buffer.get(ENCRYPTION_FLAGS_OFFSET) & USE_SHA1) != 0) {
        digest = new SHA1Digest();
      } else {
        digest = new MD5Digest();
      }

      byte[] passwordBytes = new byte[PASSWORD_LENGTH];

      if (password != null) {
        ByteBuffer bb = Column.encodeUncompressedText(
            password.toUpperCase(), charset);
        bb.get(passwordBytes, 0,
               Math.min(passwordBytes.length, bb.remaining()));
      }

      digest.update(passwordBytes, 0, passwordBytes.length);

      // Get digest value
      byte[] digestBytes = new byte[digest.getDigestSize()];
      digest.doFinal(digestBytes, 0);
      
      // Truncate to 128 bit to match Max key length as per MSDN
      if(digestBytes.length != PASSWORD_DIGEST_LENGTH) {
        digestBytes = ByteUtil.copyOf(digestBytes, PASSWORD_DIGEST_LENGTH);
      }

//       System.out.println("FOO pwdDigest " + ByteUtil.toHexString(digestBytes));

      return digestBytes;
  }

  private static byte[] concat(byte[] b1, byte[] b2) {
    byte[] out = new byte[b1.length + b2.length];
    System.arraycopy(b1, 0, out, 0, b1.length);
    System.arraycopy(b2, 0, out, b1.length, b2.length);
    return out;
  }

}
