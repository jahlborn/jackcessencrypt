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
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

import com.healthmarketscience.jackcess.ByteUtil;
import com.healthmarketscience.jackcess.PageChannel;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
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
    // FIXME, something diff for 40 bits here?
    _encKeyByteSize =  bits2bytes(_header.getKeySize());
  }

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
  protected StreamCipher initCipher() {
    return new RC4Engine();
  }

  @Override
  protected KeyParameter computeCipherParams(int pageNumber) {
    // when actually decrypting pages, we incorporate the "encoding key"
    return computeEncryptionKey(
        applyPageNumber(getEncodingKey(), 0, pageNumber));
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

    StreamCipher cipher = decryptInit(getStreamCipher(), 
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
