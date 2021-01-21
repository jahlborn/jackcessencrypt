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

package com.healthmarketscience.jackcess.crypt.impl.office;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author James Ahlborn
 */
public class ECMAStandardEncryptionProvider extends BlockCipherProvider 
{
  private static final Set<EncryptionHeader.CryptoAlgorithm> VALID_CRYPTO_ALGOS =
    EnumSet.of(EncryptionHeader.CryptoAlgorithm.AES_128,
               EncryptionHeader.CryptoAlgorithm.AES_192,
               EncryptionHeader.CryptoAlgorithm.AES_256);
  private static final Set<EncryptionHeader.HashAlgorithm> VALID_HASH_ALGOS =
    EnumSet.of(EncryptionHeader.HashAlgorithm.SHA1);
  private static final int HASH_ITERATIONS = 50000;
  
  private final int _hashIterations;
  private final EncryptionHeader _header;
  private final EncryptionVerifier _verifier;
  private final byte[] _baseHash;
  private final int _encKeyByteSize;

  public ECMAStandardEncryptionProvider(PageChannel channel, byte[] encodingKey,
                                        ByteBuffer encProvBuf, byte[] pwdBytes) 
    throws IOException
  {
    this(channel, encodingKey, encProvBuf, pwdBytes, HASH_ITERATIONS);
  }
  
  protected ECMAStandardEncryptionProvider(PageChannel channel, byte[] encodingKey,
                                           ByteBuffer encProvBuf, byte[] pwdBytes,
                                           int hashIterations) 
    throws IOException
  {
    super(channel, encodingKey);

    _hashIterations = hashIterations;

    // OC: 2.3.4.6
    _header = EncryptionHeader.read(encProvBuf, VALID_CRYPTO_ALGOS,
                                    VALID_HASH_ALGOS);

    _verifier = new EncryptionVerifier(encProvBuf, _header.getCryptoAlgorithm());

    // OC: 2.3.4.7 (part 1)
    _baseHash = hash(getDigest(), _verifier.getSalt(), pwdBytes);
    _encKeyByteSize =  bits2bytes(_header.getKeySize());
  }  
  
  @Override
  protected Digest initDigest() {
    return new SHA1Digest();
  }

  @Override
  protected BlockCipher initCipher() {
    return new AESEngine();
  }

  @Override
  protected KeyParameter computeCipherParams(int pageNumber) {
    // when actually decrypting pages, we incorporate the "encoding key"
    return computeEncryptionKey(getEncodingKey(pageNumber));
  }
  
  @Override
  protected boolean verifyPassword(byte[] pwdBytes) {

    // OC: 2.3.4.9
    BufferedBlockCipher cipher = decryptInit(getBlockCipher(), 
                                             computeEncryptionKey(int2bytes(0)));
    
    byte[] verifier = decryptBytes(cipher, _verifier.getEncryptedVerifier());
    byte[] verifierHash = 
      fixToLength(decryptBytes(cipher, _verifier.getEncryptedVerifierHash()),
                  _verifier.getVerifierHashSize());

    byte[] testHash = fixToLength(hash(getDigest(), verifier),
                                  _verifier.getVerifierHashSize());

    return Arrays.equals(verifierHash, testHash);
  }

  private KeyParameter computeEncryptionKey(byte[] blockBytes) {
    byte[] encKey = cryptDeriveKey(_baseHash, blockBytes, _encKeyByteSize);
    return new KeyParameter(encKey);
  }
  
  private byte[] cryptDeriveKey(byte[] baseHash, byte[] blockBytes, int keyByteLen)
  {
    Digest digest = getDigest();

    // OC: 2.3.4.7 (after part 1)
    byte[] iterHash = iterateHash(baseHash, _hashIterations);

    byte[] finalHash = hash(digest, iterHash, blockBytes);

    byte[] x1 = hash(digest, genXBytes(finalHash, 0x36));
    byte[] x2 = hash(digest, genXBytes(finalHash, 0x5C));
    
    return fixToLength(ByteUtil.concat(x1, x2), keyByteLen);
  }

  private static byte[] genXBytes(byte[] finalHash, int code) {
    byte[] x = fill(new byte[64], code);

    for(int i = 0; i < finalHash.length; ++i) {
      x[i] ^= finalHash[i];
    }

    return x;
  }
}

