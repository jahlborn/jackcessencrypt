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

import com.healthmarketscience.jackcess.ByteUtil;

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
      throw new IllegalStateException("salt size must be " + SALT_SIZE);
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
