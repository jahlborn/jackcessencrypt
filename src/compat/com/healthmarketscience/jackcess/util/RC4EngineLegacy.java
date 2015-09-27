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

package com.healthmarketscience.jackcess.util;

import org.bouncycastle.crypto.engines.RC4Engine;

/**
 * Simple Extension of {@link RC4Engine} which implements StreamCipherCompat
 * and allows jackcess-encrypt to work with 1.50 and earlier versions of
 * Bouncy Castle.
 *
 * @author James Ahlborn
 */
public class RC4EngineLegacy extends RC4Engine implements StreamCipherCompat
{
  static {
    try {
      // this implementation expects the processBytes method to have a void
      // return type
      if(RC4Engine.class.getMethod("processBytes", byte[].class, int.class,
                                   int.class, byte[].class, int.class)
         .getReturnType() != void.class) {
        throw new IllegalStateException("Wrong return type");
      }
    } catch(Exception e) {
      throw new IllegalStateException("Incompatible RC4Engine", e);
    }
  }
  
  /** StreamCipherFactory for this engine */
  public static final class Factory extends StreamCipherFactory {
    @Override
    public StreamCipherCompat newInstance() {
      return new RC4EngineLegacy();
    }
  }
  
  public RC4EngineLegacy() {}

  /**
   * @see RC4Engin#processBytes
   */
  public int processStreamBytes(byte[] in, int inOff,
                                int len, byte[] out, int outOff)
  {
    processBytes(in, inOff, len, out, outOff);
    return len;
  }  
}
