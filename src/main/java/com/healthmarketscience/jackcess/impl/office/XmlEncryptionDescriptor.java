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

package com.healthmarketscience.jackcess.impl.office;

import java.io.ByteArrayInputStream;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;

import com.healthmarketscience.jackcess.cryptmodel.CTEncryption;
import com.healthmarketscience.jackcess.cryptmodel.password.CTPasswordKeyEncryptor;
import org.bouncycastle.crypto.BlockCipher;
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
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.w3c.dom.Node;

/**
 *
 * @author James Ahlborn
 */
public class XmlEncryptionDescriptor 
{
  private static final String ENCRYPT_CONTEXT_NAME =
    "com.healthmarketscience.jackcess.cryptmodel";
  private static final String PASSWORD_ENCRYPTOR_CONTEXT_NAME =
    "com.healthmarketscience.jackcess.cryptmodel.password";
  // private static final String CERT_ENCRYPTOR_CONTEXT_NAME =
  //   "com.healthmarketscience.jackcess.cryptmodel.cert";

  private static final class Encypt {
    private static final JAXBContext CONTEXT = loadContext(ENCRYPT_CONTEXT_NAME);
  }
  private static final class PasswordEncryptor {
    private static final JAXBContext CONTEXT = 
      loadContext(PASSWORD_ENCRYPTOR_CONTEXT_NAME);
  }
  // private static final class CertEncryptor {
  //   private static final JAXBContext CONTEXT = 
  //     loadContext(CERT_ENCRYPTOR_CONTEXT_NAME);
  // }

  public enum CipherAlgorithm {
    AES(AESEngine.class), 
    RC2(RC2Engine.class), 
    // RC4, 
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

  private XmlEncryptionDescriptor() 
  {
  }

  public static final CTEncryption parseEncryptionDescriptor(byte[] xmlBytes) {
    try {
      return (CTEncryption)unwrap(Encypt.CONTEXT.createUnmarshaller().unmarshal(
                                      new ByteArrayInputStream(xmlBytes)));
    } catch(JAXBException e) {
      throw new IllegalStateException("Failed parsing encryption descriptor", e);
    }
  }

  public static final CTPasswordKeyEncryptor parsePasswordKeyEncryptor(
      Object keyDescriptor) {
    try {
      return (CTPasswordKeyEncryptor)unwrap(
          PasswordEncryptor.CONTEXT.createUnmarshaller().unmarshal(
              (Node)keyDescriptor));
    } catch(JAXBException e) {
      throw new IllegalStateException(
          "Failed parsing password key encryptor", e);
    }
  }  

  public static final CipherAlgorithm getAlgorithm(String str) {
    return parseEnum(str, CipherAlgorithm.class);
  }

  public static final CipherChaining getChaining(String str) {
    return parseEnum(str, CipherChaining.class);
  }

  public static final HashAlgorithm getHash(String str) {
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

  private static <E extends Enum<E>> E parseEnum(String str, Class<E> enumClazz)
  {
    String origStr = str;
    // massage the enum str a bit to be a valid enum
    str = str.trim().toUpperCase().replaceAll("[-_]", "");
    if((str.length() > 0) && Character.isDigit(str.charAt(0))) {
      str = '_' + str;
    }
    try {
      return Enum.valueOf(enumClazz, str);
    } catch(IllegalArgumentException e) {
      throw new IllegalStateException(
          "Unsupported encryption parameter: " + origStr);
    }
  }

  private static Object unwrap(Object obj) {
    if(obj instanceof JAXBElement) {
      obj = ((JAXBElement<?>)obj).getValue();
    }
    return obj;
  }

  private static <T> T newInstance(Class<? extends T> clazz) {
    try {
      return clazz.newInstance();
    } catch(Exception e) {
      throw new IllegalStateException(
          "Failed initializing encryption algorithm: " + clazz.getSimpleName(), e);
    }
  }

  private static final JAXBContext loadContext(String name) {
    try {
      return JAXBContext.newInstance(name, XmlEncryptionDescriptor.class.getClassLoader());
    } catch(JAXBException e) {
      throw new RuntimeException(e);
    }
  }
}
