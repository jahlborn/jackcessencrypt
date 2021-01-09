/*
Copyright (c) 2010 Vladimir Berezniker

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

package com.healthmarketscience.jackcess.crypt.impl;

import java.io.IOException;
import java.nio.ByteBuffer;

import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.CodecHandler;
import com.healthmarketscience.jackcess.impl.DefaultCodecProvider;
import com.healthmarketscience.jackcess.impl.JetFormat;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * CodecHandler for Jet databases.
 *
 * @author Vladimir Berezniker
 */
public class JetCryptCodecHandler extends BaseJetCryptCodecHandler
{
  final static int ENCODING_KEY_LENGTH = 0x4;

  JetCryptCodecHandler(PageChannel channel, byte[] encodingKey) {
    super(channel, encodingKey);
  }

  public static CodecHandler create(PageChannel channel)
    throws IOException
  {
    ByteBuffer buffer = readHeaderPage(channel);
    JetFormat format = channel.getFormat();

    byte[] encodingKey = ByteUtil.getBytes(buffer, format.OFFSET_ENCODING_KEY,
                                           ENCODING_KEY_LENGTH);

    return (isBlankKey(encodingKey) ? DefaultCodecProvider.DUMMY_HANDLER :
            new JetCryptCodecHandler(channel, encodingKey));
  }

  @Override
  protected KeyParameter computeCipherParams(int pageNumber) {
    return new KeyParameter(getEncodingKey(pageNumber));
  }

  @Override
  protected int getMaxEncodedPage() {
    return Integer.MAX_VALUE;
  }

}
