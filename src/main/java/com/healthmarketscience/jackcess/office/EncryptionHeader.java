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
import java.nio.CharBuffer;

import com.healthmarketscience.jackcess.ByteUtil;
import com.healthmarketscience.jackcess.UnsupportedCodecException;

/**
 *
 * @author James Ahlborn
 */
public class EncryptionHeader 
{
  static final int FCRYPTO_API_FLAG = 0x04;
  static final int FDOC_PROPS_FLAG = 0x08;
  static final int FEXTERNAL_FLAG = 0x10;
  static final int FAES_FLAG = 0x20;

  private static final int ALGID_FLAGS   = 0;
  private static final int ALGID_RC4     = 0x6801;
  private static final int ALGID_AES_128 = 0x660E;
  private static final int ALGID_AES_192 = 0x660F;
  private static final int ALGID_AES_256 = 0x6610;

  private static final int HASHALGID_FLAGS   = 0;
  private static final int HASHALGID_SHA1    = 0x8004;

  public enum CryptoAlgorithm {
    EXTERNAL(ALGID_FLAGS, 0),
    RC4(ALGID_RC4, 20), 
    AES_128(ALGID_AES_128, 32), 
    AES_192(ALGID_AES_192, 32), 
    AES_256(ALGID_AES_256, 32);

    private final int _algId;
    private final int _encVerifierHashLen;

    private CryptoAlgorithm(int algId, int encVerifierHashLen) {
      _algId = algId;
      _encVerifierHashLen = encVerifierHashLen;
    }

    public int getAlgId() {
      return _algId;
    }

    public int getEncryptedVerifierHashLen() {
      return  _encVerifierHashLen;
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
    _keySize = buffer.getInt();
    _providerType = buffer.getInt();

    // determine encryption algorithm
    _cryptoAlg = parseCryptoAlgorithm(algId, _flags);

    // determine hash algorithm
    _hashAlg = parseHashAlgorithm(algIdHash, _flags);
    
    // reserved
    buffer.getInt();
    buffer.getInt();

    _cspName = readCspName(buffer);
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

  private static String readCspName(ByteBuffer buffer) {

    // unicode string, must be multiple of 2
    int rem = (buffer.remaining() / 2) * 2;
    String cspName = "";
    if(rem > 0) {

      ByteBuffer cspNameBuf = ByteBuffer.wrap(ByteUtil.getBytes(buffer, rem));
      CharBuffer tmpCspName = 
        EncryptionProvider.UNICODE_CHARSET.decode(cspNameBuf);

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
  
  static boolean isFlagSet(int flagsVal, int flagMask)
  {
    return ((flagsVal & flagMask) != 0);
  }
}
