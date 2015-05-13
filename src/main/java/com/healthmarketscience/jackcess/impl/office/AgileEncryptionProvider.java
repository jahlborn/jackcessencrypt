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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import com.healthmarketscience.jackcess.impl.PageChannel;
import com.healthmarketscience.jackcess.cryptmodel.CTEncryption;
import com.healthmarketscience.jackcess.cryptmodel.CTKeyData;
import com.healthmarketscience.jackcess.cryptmodel.CTKeyEncryptor;
import com.healthmarketscience.jackcess.cryptmodel.password.CTPasswordKeyEncryptor;
import com.healthmarketscience.jackcess.cryptmodel.password.STPasswordKeyEncryptorUri;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 *
 * @author James Ahlborn
 */
public class AgileEncryptionProvider extends BlockCipherProvider 
{
  private static final int RESERVED_VAL = 0x40;
  private static final byte[] ENC_VERIFIER_INPUT_BLOCK = {
    (byte)0xfe, (byte)0xa7, (byte)0xd2, (byte)0x76, 
    (byte)0x3b, (byte)0x4b, (byte)0x9e, (byte)0x79};
  private static final byte[] ENC_VERIFIER_VALUE_BLOCK = {
    (byte)0xd7, (byte)0xaa, (byte)0x0f, (byte)0x6d, 
    (byte)0x30, (byte)0x61, (byte)0x34, (byte)0x4e};
  private static final byte[] ENC_VALUE_BLOCK = {
    (byte)0x14, (byte)0x6e, (byte)0x0b, (byte)0xe7, 
    (byte)0xab, (byte)0xac, (byte)0xd0, (byte)0xd6};

  private final CTEncryption _encryptDesc;
  private final CTPasswordKeyEncryptor _pwdKeyEnc;
  private final byte[] _keyValue;

  public AgileEncryptionProvider(PageChannel channel, byte[] encodingKey,
                                 ByteBuffer encProvBuf, byte[] pwdBytes) 
    throws IOException
  {
    super(channel, encodingKey);

    // OC: 2.3.4.10
    int reservedVal = encProvBuf.getInt();
    if(reservedVal != RESERVED_VAL) {
      throw new IllegalStateException("Unexpected reserved value " + reservedVal);
    }

    byte[] xmlBytes = new byte[encProvBuf.remaining()];
    encProvBuf.get(xmlBytes);
    _encryptDesc = XmlEncryptionDescriptor.parseEncryptionDescriptor(xmlBytes);

    // for now we expect a single, password key encryptor
    CTPasswordKeyEncryptor pwdKeyEnc = null;
    if((_encryptDesc.getKeyEncryptors() != null) &&
       (_encryptDesc.getKeyEncryptors().getKeyEncryptor().size() == 1)) {
      CTKeyEncryptor keyEnc = _encryptDesc.getKeyEncryptors()
        .getKeyEncryptor().get(0);
      if(STPasswordKeyEncryptorUri.HTTP_SCHEMAS_MICROSOFT_COM_OFFICE_2006_KEY_ENCRYPTOR_PASSWORD.value().equals(keyEnc.getUri())) {
        pwdKeyEnc = XmlEncryptionDescriptor.parsePasswordKeyEncryptor(
            keyEnc.getAny());
      }
    }

    if(pwdKeyEnc == null) {
      throw new IllegalStateException("Missing or unexpected key encryptor");
    }
    _pwdKeyEnc = pwdKeyEnc;

    _keyValue = decryptKeyValue(pwdBytes);
  }

  @Override
  protected Digest initPwdDigest() {
    return XmlEncryptionDescriptor.initDigest(_pwdKeyEnc.getHashAlgorithm());
  }

  @Override
  protected Digest initCryptDigest() {
    return XmlEncryptionDescriptor.initDigest(
        _encryptDesc.getKeyData().getHashAlgorithm());
  }

  @Override
  protected BlockCipher initPwdCipher() {
    return XmlEncryptionDescriptor.initCipher(
        _pwdKeyEnc.getCipherAlgorithm(), _pwdKeyEnc.getCipherChaining());
  }

  @Override
  protected BlockCipher initCryptCipher() {
    CTKeyData keyData = _encryptDesc.getKeyData();
    return XmlEncryptionDescriptor.initCipher(
        keyData.getCipherAlgorithm(), keyData.getCipherChaining());
  }

  @Override
  protected boolean verifyPassword(byte[] pwdBytes) {

    byte[] verifier = decryptVerifierHashInput(pwdBytes);
    byte[] verifierHash = decryptVerifierHashValue(pwdBytes);


    byte[] testHash = hash(getDigest(), verifier);
    int blockSize = (int)_pwdKeyEnc.getBlockSize();
    // hash length needs to be rounded up to nearest blockSize
    if((testHash.length % blockSize) != 0) {
      int hashLen = ((testHash.length + blockSize - 1) / blockSize) * blockSize;
      testHash = fixToLength(testHash, hashLen);
    }

    return Arrays.equals(verifierHash, testHash);
  }

  @Override
  protected ParametersWithIV computeCipherParams(int pageNumber) {
    // when actually decrypting pages, we incorporate the "encoding key"
    byte[] blockBytes = getEncodingKey(pageNumber);

    CTKeyData keyData = _encryptDesc.getKeyData();
    byte[] iv = cryptDeriveIV(blockBytes, keyData.getSaltValue(),
                              (int)keyData.getBlockSize());
    return new ParametersWithIV(new KeyParameter(_keyValue), iv);
  }

  private byte[] decryptVerifierHashInput(byte[] pwdBytes) {
    // OC: 2.3.4.13 (part 1)
    byte[] key = cryptDeriveKey(pwdBytes, ENC_VERIFIER_INPUT_BLOCK,
                                _pwdKeyEnc.getSaltValue(), 
                                (int)_pwdKeyEnc.getSpinCount(),
                                bits2bytes((int)_pwdKeyEnc.getKeyBits()));
  
    return blockDecryptBytes(key, _pwdKeyEnc.getSaltValue(), 
                             _pwdKeyEnc.getEncryptedVerifierHashInput());
  }

  private byte[] decryptVerifierHashValue(byte[] pwdBytes) {
    // OC: 2.3.4.13 (part 2)
    byte[] key = cryptDeriveKey(pwdBytes, ENC_VERIFIER_VALUE_BLOCK,
                                _pwdKeyEnc.getSaltValue(), 
                                (int)_pwdKeyEnc.getSpinCount(),
                                bits2bytes((int)_pwdKeyEnc.getKeyBits()));    
  
    return blockDecryptBytes(key, _pwdKeyEnc.getSaltValue(), 
                             _pwdKeyEnc.getEncryptedVerifierHashValue());
  }

  private byte[] decryptKeyValue(byte[] pwdBytes) {
    // OC: 2.3.4.13 (part 3)
    byte[] key = cryptDeriveKey(pwdBytes, ENC_VALUE_BLOCK,
                                _pwdKeyEnc.getSaltValue(), 
                                (int)_pwdKeyEnc.getSpinCount(),
                                bits2bytes((int)_pwdKeyEnc.getKeyBits()));
    
    return blockDecryptBytes(key, _pwdKeyEnc.getSaltValue(), 
                             _pwdKeyEnc.getEncryptedKeyValue());
  }

  private byte[] cryptDeriveKey(byte[] pwdBytes, byte[] blockBytes,
                                byte[] salt, int iterations, int keyByteLen)
  {
    Digest digest = getDigest();

    // OC: 2.3.4.11
    byte[] baseHash = hash(digest, salt, pwdBytes);

    byte[] iterHash = iterateHash(baseHash, iterations);

    byte[] finalHash = hash(digest, iterHash, blockBytes);

    return fixToLength(finalHash, keyByteLen, 0x36);
  }

  private byte[] cryptDeriveIV(byte[] blockBytes, byte[] salt, int keyByteLen)
  {
    // OC: 2.3.4.12
    byte[] ivBytes = ((blockBytes != null) ? 
                      hash(getDigest(), salt, blockBytes) :
                      salt);

    return fixToLength(ivBytes, keyByteLen, 0x36);
  }
}
