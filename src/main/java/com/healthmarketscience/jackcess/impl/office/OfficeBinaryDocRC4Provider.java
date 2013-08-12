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

package com.healthmarketscience.jackcess.impl.office;

import java.nio.ByteBuffer;
import java.util.Arrays;

import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author James Ahlborn
 */
public class OfficeBinaryDocRC4Provider extends StreamCipherProvider 
{
  private final byte[] _encVerifier = new byte[16];
  private final byte[] _encVerifierHash = new byte[16];
  private final byte[] _baseHash;
  
  public OfficeBinaryDocRC4Provider(PageChannel channel, byte[] encodingKey,
                                    ByteBuffer encProvBuf, byte[] pwdBytes) 
  {
    super(channel, encodingKey);

    // OC: 2.3.6.1
    byte[] salt = new byte[16];
    encProvBuf.get(salt);
    encProvBuf.get(_encVerifier);
    encProvBuf.get(_encVerifierHash);

    // OC: 2.3.6.2 (Part 1)
    byte[] fillHash = ByteUtil.concat(hash(getDigest(), pwdBytes, 5), salt);
    byte[] intBuf = new byte[336];
    for(int i = 0; i < intBuf.length; i += fillHash.length) {
      System.arraycopy(fillHash, 0, intBuf, i, fillHash.length);
    }

    _baseHash = hash(getDigest(), intBuf, 5);
  }

  public boolean canEncodePartialPage() {
    // RC4 ciphers are not influenced by the page contents, so we can easily
    // encode part of the buffer.
    return true;
  }

  @Override
  protected Digest initDigest() {
    return new MD5Digest();
  }

  @Override
  protected StreamCipher initCipher() {
    return new RC4Engine();
  }

  @Override
  protected KeyParameter computeCipherParams(int pageNumber) {
    // when actually decrypting pages, we incorporate the "encoding key"
    return computeEncryptionKey(getEncodingKey(pageNumber));
  }

  private KeyParameter computeEncryptionKey(byte[] blockBytes) {

    // OC: 2.3.6.2 (Part 2)
    byte[] encKey = hash(getDigest(), _baseHash, blockBytes, bits2bytes(128));
    return new KeyParameter(encKey);
  }

  @Override
  protected boolean verifyPassword(byte[] pwdBytes) {

    StreamCipher cipher = decryptInit(getStreamCipher(), 
                                      computeEncryptionKey(int2bytes(0)));
    
    byte[] verifier = decryptBytes(cipher, _encVerifier);
    byte[] verifierHash = decryptBytes(cipher, _encVerifierHash);

    byte[] testHash = hash(getDigest(), verifier);

    return Arrays.equals(verifierHash, testHash);
  }  
  
}
