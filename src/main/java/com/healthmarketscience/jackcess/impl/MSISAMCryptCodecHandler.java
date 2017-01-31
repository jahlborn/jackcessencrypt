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

package com.healthmarketscience.jackcess.impl;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.Arrays;

import com.healthmarketscience.jackcess.InvalidCredentialsException;
import com.healthmarketscience.jackcess.PasswordCallback;
import org.bouncycastle.crypto.Digest;
import com.healthmarketscience.jackcess.util.StreamCipherCompat;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * CodecHandler for MSISAM databases.
 *
 * @author Vladimir Berezniker
 */
public class MSISAMCryptCodecHandler extends BaseJetCryptCodecHandler
{
  private static final int SALT_OFFSET = 0x72;
  private static final int CRYPT_CHECK_START = 0x2e9;
  private static final int ENCRYPTION_FLAGS_OFFSET = 0x298;
  private static final int SALT_LENGTH = 0x4;
  private static final int PASSWORD_LENGTH = 0x28;
  private static final int USE_SHA1 = 0x20;
  private static final int PASSWORD_DIGEST_LENGTH = 0x10;
  private static final int MSISAM_MAX_ENCRYPTED_PAGE = 0xE;
   // Modern encryption using hashing
  private static final int NEW_ENCRYPTION = 0x6;
  private static final int TRAILING_PWD_LEN = 20;


  private final byte[] _baseHash;

  MSISAMCryptCodecHandler(PageChannel channel, String password, Charset charset,
                          ByteBuffer buffer) 
    throws IOException
  {
    super(channel, null);

    byte[] salt = ByteUtil.getBytes(buffer, SALT_OFFSET, 8);

    // create decryption key parts
    byte[] pwdDigest = createPasswordDigest(buffer, password, charset);
    byte[] baseSalt = ByteUtil.copyOf(salt, SALT_LENGTH);
    
    // check password hash using decryption of a known sequence
    verifyPassword(buffer, ByteUtil.concat(pwdDigest, salt), baseSalt);

    // create final key
    _baseHash = ByteUtil.concat(pwdDigest, baseSalt);
  }

  public static CodecHandler create(PasswordCallback callback, PageChannel channel, 
                                    Charset charset)
    throws IOException
  {
    ByteBuffer buffer = readHeaderPage(channel);

    if ((buffer.get(ENCRYPTION_FLAGS_OFFSET) & NEW_ENCRYPTION) != 0) {
      return new MSISAMCryptCodecHandler(channel, callback.getPassword(),
                                         charset, buffer);
    }

    // old MSISAM dbs use jet-style encryption w/ a different key
    return new JetCryptCodecHandler(channel,
        getOldDecryptionKey(buffer, channel.getFormat())) {
        @Override
        protected int getMaxEncodedPage() {
          return MSISAM_MAX_ENCRYPTED_PAGE;
        }
      };
  }

  @Override
  protected KeyParameter computeCipherParams(int pageNumber) {
    return new KeyParameter(
        applyPageNumber(_baseHash, PASSWORD_DIGEST_LENGTH, pageNumber));
  }

  @Override
  protected int getMaxEncodedPage() {
    return MSISAM_MAX_ENCRYPTED_PAGE;
  }

  private void verifyPassword(ByteBuffer buffer, byte[] testEncodingKey,
                              byte[] testBytes)
  {
    StreamCipherCompat engine = decryptInit(getStreamCipher(),
                                      new KeyParameter(testEncodingKey));

    byte[] encrypted4BytesCheck = getPasswordTestBytes(buffer);
    if(isBlankKey(encrypted4BytesCheck)) {
      // no password?
      return;
    }
    
    byte[] decrypted4BytesCheck = decryptBytes(engine, encrypted4BytesCheck);

    if (!Arrays.equals(decrypted4BytesCheck, testBytes)) {
      throw new InvalidCredentialsException("Incorrect password provided");
    }
  }

  private static byte[] createPasswordDigest(
      ByteBuffer buffer, String password, Charset charset)
  {
      Digest digest =
        (((buffer.get(ENCRYPTION_FLAGS_OFFSET) & USE_SHA1) != 0) ?
         new SHA1Digest() : new MD5Digest());

      byte[] passwordBytes = new byte[PASSWORD_LENGTH];

      if (password != null) {
        ByteBuffer bb = ColumnImpl.encodeUncompressedText(
            password.toUpperCase(), charset);
        bb.get(passwordBytes, 0,
               Math.min(passwordBytes.length, bb.remaining()));
      }

      // Get digest value
      byte[] digestBytes = hash(digest, passwordBytes, PASSWORD_DIGEST_LENGTH);
      return digestBytes;
  }

  private static byte[] getOldDecryptionKey(
      ByteBuffer buffer, JetFormat format)
  {
    byte[] encodingKey = ByteUtil.getBytes(
        buffer, SALT_OFFSET, JetCryptCodecHandler.ENCODING_KEY_LENGTH);

    // Hash the salt. Step 1.
    {
      final byte[] fullHashData = ByteUtil.getBytes(
          buffer, format.OFFSET_PASSWORD, format.SIZE_PASSWORD*2);

      // apply additional mask to header data
      byte[] pwdMask = DatabaseImpl.getPasswordMask(buffer, format);
      if(pwdMask != null) {

        for(int i = 0; i < format.SIZE_PASSWORD; ++i) {
          fullHashData[i] ^= pwdMask[i % pwdMask.length];
        }
        int trailingOffset = fullHashData.length - TRAILING_PWD_LEN;
        for(int i = 0; i < TRAILING_PWD_LEN; ++i) {
          fullHashData[trailingOffset + i] ^= pwdMask[i % pwdMask.length];
        }
      }

				
      final byte[] hashData = new byte[format.SIZE_PASSWORD];
				
      for(int pos = 0; pos < format.SIZE_PASSWORD; pos++)
      {
        hashData[pos] = fullHashData[pos*2];
      }
				
      hashSalt(encodingKey, hashData);
    }

    // Hash the salt. Step 2
    {
      byte[] jetHeader = ByteUtil.getBytes(
          buffer, JetFormat.OFFSET_ENGINE_NAME, JetFormat.LENGTH_ENGINE_NAME);
      hashSalt(encodingKey, jetHeader);
    }

    return encodingKey;
  }

  private static byte[] getPasswordTestBytes(ByteBuffer buffer)
  {      
    int cryptCheckOffset = ByteUtil.getUnsignedByte(buffer, SALT_OFFSET);
    return ByteUtil.getBytes(buffer, CRYPT_CHECK_START + cryptCheckOffset, 4);
  }

  private static void hashSalt(byte[] salt, byte[] hashData)
  {
    ByteBuffer bb = wrap(salt);

    int hash = bb.getInt();

    for(int pos = 0; pos < hashData.length; pos++)
    {
      int tmp = hashData[pos] & 0xFF;
      tmp <<= pos % 0x18;
      hash ^= tmp;
    }

    bb.rewind();
    bb.putInt(hash);
  }
	

}
