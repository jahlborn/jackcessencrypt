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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import com.healthmarketscience.jackcess.ByteUtil;
import com.healthmarketscience.jackcess.PageChannel;
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
  
  private final EncryptionHeader _header;
  private final EncryptionVerifier _verifier;
  private final byte[] _baseHash;
  private final int _encKeyByteSize;
  
  public ECMAStandardEncryptionProvider(PageChannel channel, byte[] encodingKey,
                                        ByteBuffer encProvBuf, byte[] pwdBytes) 
    throws IOException
  {
    super(channel, encodingKey);

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
    byte[] encKey = cryptDeriveKey(_baseHash, blockBytes, HASH_ITERATIONS,
                                   _encKeyByteSize);
    return new KeyParameter(encKey);
  }
  
  private byte[] cryptDeriveKey(byte[] baseHash, byte[] blockBytes, int iterations,
                                int keyByteLen)
  {
    Digest digest = getDigest();

    // OC: 2.3.4.7 (after part 1)
    byte[] iterHash = iterateHash(baseHash, iterations);

    byte[] finalHash = hash(digest, iterHash, blockBytes);

    byte[] x1 = hash(digest, genXBytes(finalHash, 0x36));
    byte[] x2 = hash(digest, genXBytes(finalHash, 0x5C));
    
    return fixToLength(ByteUtil.concat(x1, x2), keyByteLen);
  }

  private static byte[] genXBytes(byte[] finalHash, int code) {
    byte[] x = fill(new byte[64], code);

    for(int i = 0; i < finalHash.length; ++i) {
      x[0] ^= finalHash[i];
    }

    return x;
  }
}

