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

package com.healthmarketscience.jackcess;




/**
 * @deprecated replaced by {@link com.healthmarketscience.jackcess.crypt.CryptCodecProvider} (which fixes split package problem on java 9+)
 */
@Deprecated
public class CryptCodecProvider extends com.healthmarketscience.jackcess.crypt.CryptCodecProvider
{
  public CryptCodecProvider() {
    super(null, null);
  }

  public CryptCodecProvider(String password) {
    super(password, null);
  }

  public CryptCodecProvider(PasswordCallback callback) {
    super(null, callback);
  }

  @Override
  public PasswordCallback getPasswordCallback() {
    return (PasswordCallback)getPasswordSupplier();
  }

  public CryptCodecProvider setPasswordCallback(PasswordCallback newCallback) {
    setPasswordSupplier(newCallback);
    return this;
  }

}
