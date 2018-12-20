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
import java.util.EnumSet;
import java.util.Set;

import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.Digest;
import com.healthmarketscience.jackcess.util.StreamCipherCompat;
import com.healthmarketscience.jackcess.util.StreamCipherFactory;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author James Ahlborn
 */
public class RC4CryptoAPIProvider extends StreamCipherProvider 
{
  private static final Set<EncryptionHeader.CryptoAlgorithm> VALID_CRYPTO_ALGOS =
    EnumSet.of(EncryptionHeader.CryptoAlgorithm.RC4);
  private static final Set<EncryptionHeader.HashAlgorithm> VALID_HASH_ALGOS =
    EnumSet.of(EncryptionHeader.HashAlgorithm.SHA1);
  
  private final EncryptionHeader _header;
  private final EncryptionVerifier _verifier;
  private final byte[] _baseHash;
  private final int _encKeyByteSize;

  public RC4CryptoAPIProvider(PageChannel channel, byte[] encodingKey,
                              ByteBuffer encProvBuf, byte[] pwdBytes) 
  {
    super(channel, encodingKey);
    _header = EncryptionHeader.read(encProvBuf, VALID_CRYPTO_ALGOS,
                                    VALID_HASH_ALGOS);

    _verifier = new EncryptionVerifier(encProvBuf, _header.getCryptoAlgorithm());

    // OC: 2.3.5.2 (part 1)
    _baseHash = hash(getDigest(), _verifier.getSalt(), pwdBytes);
    _encKeyByteSize =  bits2bytes(_header.getKeySize());
  }

  @Override
  public boolean canEncodePartialPage() {
    // RC4 ciphers are not influenced by the page contents, so we can easily
    // encode part of the buffer.
    return true;
  }

  @Override
  protected Digest initDigest() {
    return new SHA1Digest();
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

    // OC: 2.3.5.2 (part 2)
    byte[] encKey = hash(getDigest(), _baseHash, blockBytes, _encKeyByteSize);
    if(_header.getKeySize() == 40) {
      encKey = ByteUtil.copyOf(encKey, bits2bytes(128));
    }
    return new KeyParameter(encKey);
  }

  @Override
  protected boolean verifyPassword(byte[] pwdBytes) {

    StreamCipherCompat cipher = decryptInit(getStreamCipher(), 
                                      computeEncryptionKey(int2bytes(0)));
    
    byte[] verifier = decryptBytes(cipher, _verifier.getEncryptedVerifier());
    byte[] verifierHash = 
      fixToLength(decryptBytes(cipher, _verifier.getEncryptedVerifierHash()),
                  _verifier.getVerifierHashSize());

    byte[] testHash = fixToLength(hash(getDigest(), verifier),
                                  _verifier.getVerifierHashSize());

    return Arrays.equals(verifierHash, testHash);
  }
}
