/*
Copyright (c) 2026 James Ahlborn

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


import java.io.IOException;

import com.healthmarketscience.jackcess.Database;
import com.healthmarketscience.jackcess.crypt.impl.JetPasswordHandler;


/**
 * Adds, changes and removes the database password on an open database.  The
 * current password can be read with {@link Database#getDatabasePassword},
 * which needs nothing from this library.
 * <p>
 * Only jet 4 databases (mdb files written by access 2000 and 2003) are
 * supported, and the other formats throw rather than write something ms
 * access cannot open:
 * <ul>
 * <li>jet 3 stores the password field without the creation date mask, and
 *     has not been verified</li>
 * <li>in an accdb, a database password means the file is encrypted, which is
 *     a different mechanism entirely (see {@link CryptCodecProvider})</li>
 * <li>msisam (money) files feed the password into the page encoding key</li>
 * </ul>
 * <p>
 * <b>Neither operation is atomic.</b>  Setting a password changes the page 0
 * header and rewrites every SID in the database, and the two have to agree or
 * ms access prompts for the password and then refuses to open the file.  An
 * interruption part way through leaves the database in exactly that state,
 * and re-running the operation does not repair it, because the key is derived
 * from the header the run starts with.  Copy the file first.
 * <p>
 * The database must be open for writing and must not be in concurrent use.
 *
 * @author James Ahlborn
 */
public class PasswordUtil
{
  private PasswordUtil() {}

  /**
   * Sets the database password on the given database, replacing any existing
   * one.
   *
   * @param db the database to modify, open for writing
   * @param password the new password, which may not be {@code null} or empty
   */
  public static void setDatabasePassword(Database db, String password)
    throws IOException
  {
    if((password == null) || password.isEmpty()) {
      throw new IllegalArgumentException(
          "Password may not be empty, use removeDatabasePassword instead");
    }

    new JetPasswordHandler(db).setPassword(password);
  }

  /**
   * Removes the database password from the given database.  Does nothing if
   * it does not have one.
   *
   * @param db the database to modify, open for writing
   */
  public static void removeDatabasePassword(Database db)
    throws IOException
  {
    new JetPasswordHandler(db).setPassword(null);
  }
}
