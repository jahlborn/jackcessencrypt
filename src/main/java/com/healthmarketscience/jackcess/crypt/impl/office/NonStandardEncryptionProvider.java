/*
Copyright (c) 2017 James Ahlborn

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

import java.io.IOException;
import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.impl.PageChannel;

/**
 * The "non-standard" provider handles the case where AES is enabled for older
 * databases with the office crypto "compatmode" set to 0 (non-compatible).
 * More details <a href="https://sourceforge.net/p/jackcessencrypt/bugs/6/">here</a>
 *
 * @author James Ahlborn
 */
public class NonStandardEncryptionProvider extends ECMAStandardEncryptionProvider 
{
  private static final int HASH_ITERATIONS = 0;

  public NonStandardEncryptionProvider(PageChannel channel, byte[] encodingKey,
                                        ByteBuffer encProvBuf, byte[] pwdBytes) 
    throws IOException
  {
    super(channel, encodingKey, encProvBuf, pwdBytes, HASH_ITERATIONS);
  }
}
