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

import com.healthmarketscience.jackcess.crypt.InvalidCryptoConfigurationException;
import com.healthmarketscience.jackcess.crypt.model.CTEncryption;
import com.healthmarketscience.jackcess.crypt.util.StreamCipherCompat;
import com.healthmarketscience.jackcess.crypt.util.StreamCipherFactory;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 *
 * @author James Ahlborn
 */
@SuppressWarnings("deprecation")
public class XmlEncryptionDescriptor
{
  // this value doesn't matter, just multiple of 2
  private static final int STREAM_CIPHER_BLOCK_SIZE = 16;

  public enum CipherAlgorithm {
    AES(AESEngine.class),
    RC2(RC2Engine.class),
    RC4(RC4BlockCipher.class),
    DES(DESEngine.class),
    // DESX,
    _3DES(DESedeEngine.class),
    _3DES112(DESedeEngine.class)
    ;

    private final Class<? extends BlockCipher> _blockCipherClazz;

    private CipherAlgorithm(Class<? extends BlockCipher> blockCipherClazz) {
      _blockCipherClazz = blockCipherClazz;
    }

    public BlockCipher initBlockCipher() {
      return newInstance(_blockCipherClazz);
    }
  }

  public enum CipherChaining {
    CHAININGMODECBC {
      @Override public BlockCipher initChainingMode(BlockCipher baseCipher) {
        return new CBCBlockCipher(baseCipher);
      }
    },
    CHAININGMODECFB {
      @Override public BlockCipher initChainingMode(BlockCipher baseCipher) {
        return new CFBBlockCipher(baseCipher, 8);
      }
    },
    CHAININGMODECCM {
      @Override public BlockCipher initChainingMode(BlockCipher baseCipher) {
        return new AEADBlockCipherAdapter(new CCMBlockCipher(baseCipher));
      }
    },
    CHAININGMODEGCM {
      @Override public BlockCipher initChainingMode(BlockCipher baseCipher) {
        return new AEADBlockCipherAdapter(new GCMBlockCipher(baseCipher));
      }
    },
    CHAININGMODEECB {
      @Override public BlockCipher initChainingMode(BlockCipher baseCipher) {
        return new ECBBlockCipher(baseCipher);
      }
    };

    public abstract BlockCipher initChainingMode(BlockCipher baseCipher);
  }

  public enum HashAlgorithm {
    SHA1(SHA1Digest.class),
    SHA256(SHA256Digest.class),
    SHA384(SHA384Digest.class),
    SHA512(SHA512Digest.class),
    MD5(MD5Digest.class),
    MD4(MD4Digest.class),
    MD2(MD2Digest.class),
    RIPEMD128(RIPEMD128Digest.class),
    RIPEMD160(RIPEMD160Digest.class),
    WHIRLPOOL(WhirlpoolDigest.class);

    private final Class<? extends Digest> _digestClazz;

    private HashAlgorithm(Class<? extends Digest> digestClazz) {
      _digestClazz = digestClazz;
    }

    public Digest initDigest() {
      return newInstance(_digestClazz);
    }
  }

  private XmlEncryptionDescriptor() {}

  public static final CTEncryption parseEncryptionDescriptor(byte[] xmlBytes) {
    return XmlEncryptionParser.parseEncryptionDescriptor(xmlBytes);
  }

  private static final CipherAlgorithm getAlgorithm(String str) {
    return parseEnum(str, CipherAlgorithm.class);
  }

  private static final CipherChaining getChaining(String str) {
    return parseEnum(str, CipherChaining.class);
  }

  private static final HashAlgorithm getHash(String str) {
    return parseEnum(str, HashAlgorithm.class);
  }

  public static final Digest initDigest(String str) {
    return getHash(str).initDigest();
  }

  public static final BlockCipher initCipher(String cipherStr,
                                             String chainStr) {
    return getChaining(chainStr).initChainingMode(
        getAlgorithm(cipherStr).initBlockCipher());
  }

  private static <E extends Enum<E>> E parseEnum(String str, Class<E> enumClazz) {
    String origStr = str;
    // massage the enum str a bit to be a valid enum
    str = str.trim().toUpperCase().replaceAll("[-_]", "");
    if((str.length() > 0) && Character.isDigit(str.charAt(0))) {
      str = '_' + str;
    }
    try {
      return Enum.valueOf(enumClazz, str);
    } catch(IllegalArgumentException e) {
      throw new InvalidCryptoConfigurationException(
          "Unsupported encryption parameter: " + origStr);
    }
  }

  private static <T> T newInstance(Class<? extends T> clazz) {
    try {
      return clazz.newInstance();
    } catch(Exception e) {
      throw new InvalidCryptoConfigurationException(
          "Failed initializing encryption algorithm: " + clazz.getSimpleName(), e);
    }
  }

  private static final class AEADBlockCipherAdapter implements BlockCipher
  {
    private final AEADBlockCipher _cipher;

    private AEADBlockCipherAdapter(AEADBlockCipher cipher) {
      _cipher = cipher;
    }

    @Override
    public String getAlgorithmName() {
      return _cipher.getAlgorithmName();
    }

    @Override
    public int getBlockSize() {
      return _cipher.getUnderlyingCipher().getBlockSize();
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) {
      _cipher.init(forEncryption, params);
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
      return _cipher.processBytes(in, inOff, getBlockSize(), out, outOff);
    }

    @Override
    public void reset() {
      _cipher.reset();
    }
  }

  private static final class ECBBlockCipher implements BlockCipher
  {
    private final BlockCipher _cipher;

    private ECBBlockCipher(BlockCipher cipher) {
      _cipher = cipher;
    }

    @Override
    public String getAlgorithmName() {
      return _cipher.getAlgorithmName();
    }

    @Override
    public int getBlockSize() {
      return _cipher.getBlockSize();
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) {
      if(params instanceof ParametersWithIV) {
        _cipher.init(forEncryption, ((ParametersWithIV)params).getParameters());
      } else if(params instanceof KeyParameter) {
        _cipher.init(forEncryption, params);
      } else {
        throw new IllegalArgumentException("invalid parameters passed to ECB");
      }
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
      return _cipher.processBlock(in, inOff, out, outOff);
    }

    @Override
    public void reset() {
      _cipher.reset();
    }
  }

  private static class BlockCipherAdapter implements BlockCipher
  {
    private final StreamCipherCompat _cipher;

    private BlockCipherAdapter(StreamCipherCompat cipher) {
      _cipher = cipher;
    }

    @Override
    public String getAlgorithmName() {
      return _cipher.getAlgorithmName();
    }

    @Override
    public int getBlockSize() {
      return STREAM_CIPHER_BLOCK_SIZE;
    }

    @Override
    public void init(boolean forEncryption, CipherParameters params) {
      if(params instanceof ParametersWithIV) {
        _cipher.init(forEncryption, ((ParametersWithIV)params).getParameters());
      } else if(params instanceof KeyParameter) {
        _cipher.init(forEncryption, params);
      } else {
        throw new IllegalArgumentException("invalid parameters passed to " +
                                           getAlgorithmName());
      }
    }

    @Override
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) {
      _cipher.processStreamBytes(in, inOff, STREAM_CIPHER_BLOCK_SIZE, out, outOff);
      return STREAM_CIPHER_BLOCK_SIZE;
    }

    @Override
    public void reset() {
      _cipher.reset();
    }
  }

  public static final class RC4BlockCipher extends BlockCipherAdapter
  {
    public RC4BlockCipher() {
      super(StreamCipherFactory.newRC4Engine());
    }
  }

}
