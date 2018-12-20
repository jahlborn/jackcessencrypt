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

package com.healthmarketscience.jackcess.impl.office;

import java.nio.ByteBuffer;
import java.util.Arrays;

import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.Digest;
import com.healthmarketscience.jackcess.util.StreamCipherCompat;
import com.healthmarketscience.jackcess.util.StreamCipherFactory;
import org.bouncycastle.crypto.digests.MD5Digest;
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

  @Override
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
  protected StreamCipherCompat initCipher() {
    return StreamCipherFactory.newRC4Engine();
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

    StreamCipherCompat cipher = decryptInit(getStreamCipher(), 
                                      computeEncryptionKey(int2bytes(0)));
    
    byte[] verifier = decryptBytes(cipher, _encVerifier);
    byte[] verifierHash = decryptBytes(cipher, _encVerifierHash);

    byte[] testHash = hash(getDigest(), verifier);

    return Arrays.equals(verifierHash, testHash);
  }  
  
}
