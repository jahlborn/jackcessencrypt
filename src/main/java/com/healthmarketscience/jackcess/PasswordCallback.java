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

package com.healthmarketscience.jackcess;

/**
 * Callback which can be used by CryptCodecProvider to retrieve a password on
 * demand, at the time it is required.  The callback will only be invoked if
 * it is determined that a file <i>actually</i> requires a password to be
 * opened.  This could be used to implement a password user prompt utility.
 *
 * @author James Ahlborn
 */
public interface PasswordCallback 
{
  /**
   * Invoked by CryptCodecProvider when a password is necessary to open an
   * access database.
   *
   * @return the required password
   */
    public String getPassword();
}
