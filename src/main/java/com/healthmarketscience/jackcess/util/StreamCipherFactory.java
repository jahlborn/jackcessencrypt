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

/**
 * Factory for instantiating {@link StreamCipher} instances.  Bouncy Castle
 * 1.51 made a binary incompatible change to the StreamCipher API.  This
 * factory enables jackcess-encrypt to function with both the pre 1.51 API as
 * well as the 1.51+ API.
 *
 * @author James Ahlborn
 */
public abstract class StreamCipherFactory 
{
  /** compatible factory for RC4Engine instances */
  private static final StreamCipherFactory RC4_ENGINE_FACTORY;  
  static {
    StreamCipherFactory factory = null;
    try {
      // first, attempt to load a 1.51+ compatible factory instance
      factory = loadFactory("com.healthmarketscience.jackcess.util.RC4EngineCompat$Factory");
    } catch(Throwable t) {
      // failed, try legacy version
    }

    if(factory == null) {
      try {
        // now, attempt to load a 1.50 and earlier compatible factory instance
        factory = loadFactory("com.healthmarketscience.jackcess.util.RC4EngineLegacy$Factory");
      } catch(Exception e) {
        // sorry, no dice
        throw new IllegalStateException("Incompatible bouncycastle version", e);
      }
    }

    RC4_ENGINE_FACTORY = factory;
  }
  
  protected StreamCipherFactory() {}

  public static StreamCipherCompat newRC4Engine() {
    return RC4_ENGINE_FACTORY.newInstance();
  }

  private static StreamCipherFactory loadFactory(String className)
    throws Exception
  {
    Class<?> factoryClass = Class.forName(className);
    StreamCipherFactory factory = (StreamCipherFactory)factoryClass.newInstance();
    // verify that the engine is functional
    if(factory.newInstance() == null) {
      throw new IllegalStateException("EngineFactory " + className +
                                      " not functional");
    }
    return factory;
  }

  public abstract StreamCipherCompat newInstance();
}
