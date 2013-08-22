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
