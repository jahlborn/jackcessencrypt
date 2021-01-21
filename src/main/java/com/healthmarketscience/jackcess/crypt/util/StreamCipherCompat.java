/*
Copyright (c) 2015 James Ahlborn

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

package com.healthmarketscience.jackcess.crypt.util;

import org.bouncycastle.crypto.CipherParameters;

/**
 * Alternate version of StreamCipher API which allows us to be handle both old
 * and new bouncycastle versions.
 *
 * @see org.bouncycastle.crypto.StreamCipher
 * 
 * @author James Ahlborn
 */
public interface StreamCipherCompat 
{
  public String getAlgorithmName();

  public void init(boolean forEncryption, CipherParameters params);

  public byte returnByte(byte in);

  public int processStreamBytes(byte[] in, int inOff,
                                int len, byte[] out, int outOff);

  public void reset();
}
