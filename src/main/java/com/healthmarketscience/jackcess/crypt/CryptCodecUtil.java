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

package com.healthmarketscience.jackcess.crypt;

import com.healthmarketscience.jackcess.DatabaseBuilder;

/**
 * Utility class for configuring the {@link CryptCodecProvider} on the given
 * {@link DatabaseBuilder}.
 *
 * @author James Ahlborn
 */
public class CryptCodecUtil
{

  private CryptCodecUtil() {}

  /**
   * Configures a new CryptCodecProvider on the given DatabaseBuilder.
   */
  public static DatabaseBuilder setProvider(DatabaseBuilder db) {
    return db.setCodecProvider(new CryptCodecProvider());
  }

  /**
   * Configures a new CryptCodecProvider with the given password on the given
   * DatabaseBuilder.
   */
  public static DatabaseBuilder setProvider(DatabaseBuilder db, String pwd) {
    return db.setCodecProvider(new CryptCodecProvider(pwd));
  }

}
