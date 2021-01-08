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
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.util.Set;

import com.healthmarketscience.jackcess.crypt.InvalidCryptoConfigurationException;
import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.CustomToStringStyle;
import com.healthmarketscience.jackcess.impl.UnsupportedCodecException;
import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 *
 * @author James Ahlborn
 */
public class EncryptionHeader
{
  public static final Charset UNICODE_CHARSET = Charset.forName("UTF-16LE");

  public static final int FCRYPTO_API_FLAG = 0x04;
  public static final int FDOC_PROPS_FLAG = 0x08;
  public static final int FEXTERNAL_FLAG = 0x10;
  public static final int FAES_FLAG = 0x20;

  private static final int ALGID_FLAGS   = 0;
  private static final int ALGID_RC4     = 0x6801;
  private static final int ALGID_AES_128 = 0x660E;
  private static final int ALGID_AES_192 = 0x660F;
  private static final int ALGID_AES_256 = 0x6610;

  private static final int HASHALGID_FLAGS   = 0;
  private static final int HASHALGID_SHA1    = 0x8004;

  private static final String CSP_BASE_STRING = " base ";
  private static final int RC4_BASE_DEFAULT_KEY_SIZE = 0x28;
  private static final int RC4_STRONG_DEFAULT_KEY_SIZE = 0x80;

  public enum CryptoAlgorithm {
    EXTERNAL(ALGID_FLAGS, 0, 0, 0),
    // the CryptoAPI gives a valid range of 40-128 bits.  the CNG spec
    // (http://msdn.microsoft.com/en-us/library/windows/desktop/bb931354%28v=vs.85%29.aspx)
    // gives a range from 8-512 bits.  bouncycastle supports 40-2048 bits.
    RC4(ALGID_RC4, 20, 0x28, 0x200),
    AES_128(ALGID_AES_128, 32, 0x80, 0x80),
    AES_192(ALGID_AES_192, 32, 0xC0, 0xC0),
    AES_256(ALGID_AES_256, 32, 0x100, 0x100);

    private final int _algId;
    private final int _encVerifierHashLen;
    private final int _keySizeMin;
    private final int _keySizeMax;

    private CryptoAlgorithm(int algId, int encVerifierHashLen,
                            int keySizeMin, int keySizeMax) {
      _algId = algId;
      _encVerifierHashLen = encVerifierHashLen;
      _keySizeMin = keySizeMin;
      _keySizeMax = keySizeMax;
    }

    public int getAlgId() {
      return _algId;
    }

    public int getKeySizeMin() {
      return _keySizeMin;
    }

    public int getEncryptedVerifierHashLen() {
      return  _encVerifierHashLen;
    }

    public boolean isValidKeySize(int keySize) {
      return ((_keySizeMin <= keySize) && (keySize <= _keySizeMax));
    }
  }

  public enum HashAlgorithm {
    EXTERNAL(HASHALGID_FLAGS),
    SHA1(HASHALGID_SHA1);

    private final int _algId;

    private HashAlgorithm(int algId) {
      _algId = algId;
    }

    public int getAlgId() {
      return _algId;
    }
  }

  private final int _flags;
  private final int _sizeExtra;
  private final CryptoAlgorithm _cryptoAlg;
  private final HashAlgorithm _hashAlg;
  private final int _keySize;
  private final int _providerType;
  private final String _cspName;

  public EncryptionHeader(ByteBuffer buffer)
  {
    // OC: 2.3.2 EncryptionHeader Structure
    _flags = buffer.getInt();
    _sizeExtra = buffer.getInt();
    int algId = buffer.getInt();
    int algIdHash = buffer.getInt();
    int keySize = buffer.getInt();
    _providerType = buffer.getInt();

    // determine encryption algorithm
    _cryptoAlg = parseCryptoAlgorithm(algId, _flags);

    // determine hash algorithm
    _hashAlg = parseHashAlgorithm(algIdHash, _flags);

    // reserved
    buffer.getInt();
    buffer.getInt();

    _cspName = readCspName(buffer);

    _keySize = parseKeySize(keySize, _cryptoAlg, _cspName);
  }

  public int getFlags() {
    return _flags;
  }

  public int getSizeExtra() {
    return _sizeExtra;
  }

  public CryptoAlgorithm getCryptoAlgorithm() {
    return _cryptoAlg;
  }

  public HashAlgorithm getHashAlgorithm() {
    return _hashAlg;
  }

  public int getKeySize() {
    return _keySize;
  }

  public int getProviderType() {
    return _providerType;
  }

  public String getCspName() {
    return _cspName;
  }

  public static EncryptionHeader read(ByteBuffer encProvBuf,
                                      Set<CryptoAlgorithm> validCryptoAlgos,
                                      Set<HashAlgorithm> validHashAlgos)
  {
    // read length of header
    int headerLen = encProvBuf.getInt();

    // read header (temporarily narrowing buf to header)
    int origLimit = encProvBuf.limit();
    int startPos = encProvBuf.position();
    encProvBuf.limit(startPos + headerLen);

    EncryptionHeader header = null;
    try {
      header = new EncryptionHeader(encProvBuf);

      // verify parameters
      if(!validCryptoAlgos.contains(header.getCryptoAlgorithm())) {
        throw new InvalidCryptoConfigurationException(
            header + " crypto algorithm must be one of " + validCryptoAlgos);
      }

      if(!validHashAlgos.contains(header.getHashAlgorithm())) {
        throw new InvalidCryptoConfigurationException(
            header + " hash algorithm must be one of " + validHashAlgos);
      }

      int keySize = header.getKeySize();
      if(!header.getCryptoAlgorithm().isValidKeySize(keySize)) {
        throw new InvalidCryptoConfigurationException(
            header + " key size is outside allowable range");
      }
      if((keySize % 8) != 0) {
        throw new InvalidCryptoConfigurationException(
            header + " key size must be multiple of 8");
      }

    } finally {
      // restore original limit
      encProvBuf.limit(origLimit);
    }

    // move to after header
    encProvBuf.position(startPos + headerLen);

    return header;
  }

  private static CryptoAlgorithm parseCryptoAlgorithm(
      int algId, int flags)
  {
    switch(algId) {
    case ALGID_FLAGS:
      if(isFlagSet(flags, FEXTERNAL_FLAG)) {
        return CryptoAlgorithm.EXTERNAL;
      }
      if(isFlagSet(flags, FCRYPTO_API_FLAG)) {
        return (isFlagSet(flags, FAES_FLAG) ?
                CryptoAlgorithm.AES_128 :
                CryptoAlgorithm.RC4);
      }
      break;
    case ALGID_RC4:
      return CryptoAlgorithm.RC4;
    case ALGID_AES_128:
      return CryptoAlgorithm.AES_128;
    case ALGID_AES_192:
      return CryptoAlgorithm.AES_192;
    case ALGID_AES_256:
      return CryptoAlgorithm.AES_256;
    }

    throw new UnsupportedCodecException(
        "Unsupported encryption algorithm " + algId + " (flags " +
        flags +")");
  }

  private static HashAlgorithm parseHashAlgorithm(int algIdHash, int flags)
  {
    switch(algIdHash) {
    case HASHALGID_FLAGS:
      if(isFlagSet(flags, FEXTERNAL_FLAG)) {
        return HashAlgorithm.EXTERNAL;
      }
      return HashAlgorithm.SHA1;
    case HASHALGID_SHA1:
      return HashAlgorithm.SHA1;
    }

    throw new UnsupportedCodecException(
        "Unsupported hash algorithm " + algIdHash + " (flags " +
        flags +")");
  }

  private static int parseKeySize(int keySize, CryptoAlgorithm cryptoAlg,
                                  String cspName)
  {
    if(keySize != 0) {
      return keySize;
    }

    // if keySize is 0, then use algorithm/provider default
    if(cryptoAlg == CryptoAlgorithm.RC4) {

      // the default key size depends on the crypto service provider.  if the
      // provider name was not given, or contains the string " base " use the
      // Base provider default.  otherwise, use the Strong provider default.
      // CSPs: http://msdn.microsoft.com/en-us/library/windows/desktop/bb931357%28v=vs.85%29.aspx
      cspName = cspName.trim().toLowerCase();
      return (((cspName.length() == 0) || cspName.contains(CSP_BASE_STRING))
              ? RC4_BASE_DEFAULT_KEY_SIZE : RC4_STRONG_DEFAULT_KEY_SIZE);
    }

    // for all other algorithms, use min key size
    return cryptoAlg.getKeySizeMin();
  }

  private static String readCspName(ByteBuffer buffer) {

    // unicode string, must be multiple of 2
    int rem = (buffer.remaining() / 2) * 2;
    String cspName = "";
    if(rem > 0) {

      ByteBuffer cspNameBuf = ByteBuffer.wrap(ByteUtil.getBytes(buffer, rem));
      CharBuffer tmpCspName = UNICODE_CHARSET.decode(cspNameBuf);

      // should be null terminated, strip that
      for(int i = 0; i < tmpCspName.limit(); ++i) {
        if(tmpCspName.charAt(i) == '\0') {
          tmpCspName.limit(i);
          break;
        }
      }

      cspName = tmpCspName.toString();
    }

    return cspName;
  }

  public static boolean isFlagSet(int flagsVal, int flagMask)
  {
    return ((flagsVal & flagMask) != 0);
  }

  @Override
  public String toString()
  {
    return ToStringBuilder.reflectionToString(this, CustomToStringStyle.VALUE_INSTANCE);
  }
}
