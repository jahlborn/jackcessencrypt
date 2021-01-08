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

import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.crypt.InvalidCryptoConfigurationException;
import com.healthmarketscience.jackcess.impl.ByteUtil;

/**
 *
 * @author James Ahlborn
 */
public class EncryptionVerifier
{
  private final static int SALT_SIZE = 16;
  private final static int ENC_VERIFIER_SIZE = 16;

  private final int _saltSize;
  private final byte[] _salt;
  private final byte[] _encryptedVerifier;
  private final int _verifierHashSize;
  private final byte[] _encryptedVerifierHash;

  public EncryptionVerifier(ByteBuffer buffer,
                            EncryptionHeader.CryptoAlgorithm cryptoAlg)
  {
    // OC: 2.3.3 EncryptionVerifier Structure
    _saltSize = buffer.getInt();
    if(_saltSize != SALT_SIZE) {
      throw new InvalidCryptoConfigurationException("salt size " + _saltSize + " must be " + SALT_SIZE);
    }
    _salt = ByteUtil.getBytes(buffer, _saltSize);
    _encryptedVerifier = ByteUtil.getBytes(buffer, ENC_VERIFIER_SIZE);
    _verifierHashSize = buffer.getInt();
    _encryptedVerifierHash = ByteUtil.getBytes(
        buffer, cryptoAlg.getEncryptedVerifierHashLen());
  }

  public int getSaltSize() {
    return _saltSize;
  }

  public byte[] getSalt() {
    return _salt;
  }

  public byte[] getEncryptedVerifier() {
    return _encryptedVerifier;
  }

  public int getVerifierHashSize() {
    return _verifierHashSize;
  }

  public byte[] getEncryptedVerifierHash() {
    return _encryptedVerifierHash;
  }

}
