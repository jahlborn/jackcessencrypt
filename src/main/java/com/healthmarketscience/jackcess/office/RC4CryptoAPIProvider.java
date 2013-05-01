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

import com.healthmarketscience.jackcess.BaseCryptCodecHandler;
import com.healthmarketscience.jackcess.ByteUtil;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 *
 * @author James Ahlborn
 */
public class RC4CryptoAPIProvider extends EncryptionProvider 
{
  private static final int MIN_KEY_SIZE = 0x28;
  private static final int MAX_KEY_SIZE = 0x80;
  
  private final EncryptionHeader _header;
  private final EncryptionVerifier _verifier;
  private final byte[] _baseHash;
  private final int _encKeyByteSize;
  private final byte[] _pwdBytes;

  public RC4CryptoAPIProvider(ByteBuffer encProvBuf, byte[] pwdBytes) 
  {
    _pwdBytes = pwdBytes;
    _header = readEncryptionHeader(encProvBuf);
    System.out.println("FOO header " + _header.getCspName());

    // verify some expected header values
    if(_header.getCryptoAlgorithm() != EncryptionHeader.CryptoAlgorithm.RC4) {
      throw new IllegalStateException(this + " crypto algorithm must be " +
                                      EncryptionHeader.CryptoAlgorithm.RC4);
    }

    if(_header.getHashAlgorithm() != EncryptionHeader.HashAlgorithm.SHA1) {
      throw new IllegalStateException(this + " hash algorithm must be " +
                                      EncryptionHeader.HashAlgorithm.SHA1);
    }
    
    int keySize = _header.getKeySize();
    if((keySize < MIN_KEY_SIZE) || (keySize > MAX_KEY_SIZE)) {
      throw new IllegalStateException(
          this + " key size is outside allowable range");
    }
    if((keySize % 8) != 0) {
      throw new IllegalStateException(
          this + " key size must be multiple of 8");      
    }

    _verifier = new EncryptionVerifier(encProvBuf, _header.getCryptoAlgorithm());

    Digest digest = getDigest();

    // OC: 2.3.5.2 (part 1)
    _baseHash = BaseCryptCodecHandler.hash(
        digest, _verifier.getSalt(), pwdBytes);
    // FIXME, something diff for 40 bits here?
    _encKeyByteSize = _header.getKeySize() / 8;
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
  protected byte[] getEncryptionKey(int pageNumber) {
    // OC: 2.3.5.2 (part 2)
    byte[] encKey = BaseCryptCodecHandler.hash(getDigest(), 
                                               _baseHash,
                                               int2bytes(pageNumber), 
                                               _encKeyByteSize);
    if(_header.getKeySize() == 40) {
      encKey = ByteUtil.copyOf(encKey, 128/8);
    }
    return encKey;

    // return BaseCryptCodecHandler.applyPageNumber(
    //     ByteUtil.concat(_baseHash, _verifier.getSalt()), 16, pageNumber);

    // FIXME
    // return cryptDeriveKey(_pwdBytes, pageNumber, _verifier.getSalt(),
    //                       50000, _encKeyByteSize);
  }

  @Override
  protected boolean verifyPassword(String password) {
    byte[] encKey = getEncryptionKey(0);
    StreamCipher cipher = getCipher();
    cipher.init(false, new KeyParameter(encKey));
    
    byte[] verifier = decryptBytes(cipher, _verifier.getEncryptedVerifier());
    byte[] verifierHash = 
      BaseCryptCodecHandler.fixToLength(
          decryptBytes(cipher, _verifier.getEncryptedVerifierHash()),
          _verifier.getVerifierHashSize());

    byte[] testHash = BaseCryptCodecHandler.fixToLength(
        BaseCryptCodecHandler.hash(getDigest(), verifier),
        _verifier.getVerifierHashSize());

    return Arrays.equals(verifierHash, testHash);
  }

  private byte[] cryptDeriveKey(byte[] pwdBytes, int pageNumber,
                                byte[] salt, int iterations, int keyByteLen)
  {
    Digest digest = getDigest();

    // OC: 2.3.4.7
    byte[] baseHash = BaseCryptCodecHandler.hash(
        digest, salt, pwdBytes);

    byte[] iterHash = iterateHash(baseHash, iterations);

    byte[] finalHash = BaseCryptCodecHandler.hash(
        digest, iterHash, int2bytes(pageNumber));

    byte[] x1 = BaseCryptCodecHandler.hash(
        digest, genXBytes(finalHash, (byte)0x36));
    byte[] x2 = BaseCryptCodecHandler.hash(
        digest, genXBytes(finalHash, (byte)0x5C));
    
    return BaseCryptCodecHandler.fixToLength(ByteUtil.concat(x1, x2), keyByteLen);
  }

  private static byte[] genXBytes(byte[] finalHash, byte code) {
    byte[] x = new byte[64];
    Arrays.fill(x, code);

    for(int i = 0; i < finalHash.length; ++i) {
      x[0] ^= finalHash[i];
    }

    return x;
  }

  protected static byte[] decryptBytes(StreamCipher cipher, byte[] encBytes)
  {
    byte[] bytes = new byte[encBytes.length];
    cipher.processBytes(encBytes, 0, encBytes.length, bytes, 0);
    return bytes;
  }
}
