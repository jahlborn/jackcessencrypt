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


import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.healthmarketscience.jackcess.Column;
import com.healthmarketscience.jackcess.Database;
import com.healthmarketscience.jackcess.DatabaseBuilder;
import com.healthmarketscience.jackcess.Row;
import com.healthmarketscience.jackcess.Table;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;


/**
 * The expected files were produced by ms access itself, adding and removing
 * the password on the same databases, so every assertion here compares
 * against what the engine actually wrote.
 *
 * @author James Ahlborn
 */
public class PasswordUtilTest
{
  private static final String DIR = "src/test/data/";
  private static final String PWD = "testpassword";

  /** page 0 offset and length of the password field for jet 4 */
  private static final int OFF_PWD = 66;
  private static final int LEN_PWD = 40;
  private static final int PAGE_SIZE = 4096;

  /** the columns which carry a masked SID */
  private static final String[][] SID_COLUMNS = {
    {"MSysACEs", "SID"},
    {"MSysObjects", "Owner"},
  };

  @Test
  public void testSetPassword() throws Exception
  {
    doTestSetPassword("pwd-none.mdb", PWD, "pwd-set.mdb");
  }

  @Test
  public void testRemovePassword() throws Exception
  {
    doTestSetPassword("pwd-set.mdb", null, "pwd-removed.mdb");
  }

  /**
   * The same password on a database with a different creation date, which
   * gets a different key, so this fails if the creation date is dropped from
   * the fold.
   */
  @Test
  public void testSetPasswordOtherCreationDate() throws Exception
  {
    doTestSetPassword("pwd2-none.mdb", PWD, "pwd2-set.mdb");
  }

  @Test
  public void testRemovePasswordOtherCreationDate() throws Exception
  {
    doTestSetPassword("pwd2-set.mdb", null, "pwd2-none.mdb");
  }

  /**
   * Setting a password and removing it again has to leave the password field
   * and every SID exactly as they started.
   */
  @Test
  public void testRoundTrip() throws Exception
  {
    File dbFile = copyToTemp("pwd-none.mdb");
    byte[] origPage0 = readPage0(dbFile);
    List<String> origSids = readSids(dbFile);

    Database db = new DatabaseBuilder(dbFile).open();
    try {
      PasswordUtil.setDatabasePassword(db, PWD);
      assertEquals(PWD, db.getDatabasePassword());
      assertFalse(origSids.equals(readSids(db)));

      PasswordUtil.removeDatabasePassword(db);
      assertNull(db.getDatabasePassword());
      assertEquals(origSids, readSids(db));
    } finally {
      db.close();
    }

    assertArrayEquals(pwdField(origPage0), pwdField(readPage0(dbFile)));
  }

  /**
   * Removing a password which is not there changes nothing.
   */
  @Test
  public void testRemoveMissingPassword() throws Exception
  {
    File dbFile = copyToTemp("pwd-none.mdb");
    byte[] origPage0 = readPage0(dbFile);
    List<String> origSids = readSids(dbFile);

    Database db = new DatabaseBuilder(dbFile).open();
    try {
      PasswordUtil.removeDatabasePassword(db);
      assertNull(db.getDatabasePassword());
    } finally {
      db.close();
    }

    assertArrayEquals(origPage0, readPage0(dbFile));
    assertEquals(origSids, readSids(dbFile));
  }

  /**
   * An accdb password means the file is encrypted, which is a different
   * mechanism entirely.  (jet 3 needs no test: jackcess treats that format as
   * read-only, so it cannot reach this code at all.)
   */
  @Test
  public void testUnsupportedAccdb() throws Exception
  {
    File dbFile = File.createTempFile("pwdtest", ".accdb");
    dbFile.deleteOnExit();
    assertTrue(dbFile.delete());

    Database db = new DatabaseBuilder(dbFile)
      .setFileFormat(Database.FileFormat.V2010).create();
    try {
      doTestUnsupportedFormat(db);
    } finally {
      db.close();
    }
  }

  /**
   * An msisam file feeds the password into the page encoding key, so writing
   * the field would break the file.  This is the rejection that matters most,
   * since the format is writable and looks like jet 4.
   */
  @Test
  public void testUnsupportedMsisam() throws Exception
  {
    File dbFile = copyToTemp("money2001.mny", ".mny");

    Database db = new DatabaseBuilder(dbFile)
      .setCodecProvider(new CryptCodecProvider()).open();
    try {
      doTestUnsupportedFormat(db);
    } finally {
      db.close();
    }
  }

  @Test
  public void testReadOnly() throws Exception
  {
    File dbFile = copyToTemp("pwd-none.mdb");
    Database db = new DatabaseBuilder(dbFile).setReadOnly(true).open();
    try {
      PasswordUtil.setDatabasePassword(db, PWD);
      fail("IllegalStateException should have been thrown");
    } catch(IllegalStateException e) {
      // success
    } finally {
      db.close();
    }

    assertNull(readPassword(dbFile));
  }

  @Test
  public void testInvalidPassword() throws Exception
  {
    File dbFile = copyToTemp("pwd-none.mdb");
    Database db = new DatabaseBuilder(dbFile).open();
    try {

      for(String pwd : Arrays.asList(null, "")) {
        try {
          PasswordUtil.setDatabasePassword(db, pwd);
          fail("IllegalArgumentException should have been thrown");
        } catch(IllegalArgumentException e) {
          // success
        }
      }

      // jet 4 stores 40 bytes of utf-16, so 20 characters
      PasswordUtil.setDatabasePassword(db, createString(20));

      try {
        PasswordUtil.setDatabasePassword(db, createString(21));
        fail("IllegalArgumentException should have been thrown");
      } catch(IllegalArgumentException e) {
        // success
      }

      assertEquals(createString(20), db.getDatabasePassword());

    } finally {
      db.close();
    }
  }

  /**
   * Applies the given password change to a copy of the given database and
   * checks the result against the file ms access produced for the same
   * change.
   */
  private void doTestSetPassword(String srcName, String password,
                                 String expectedName)
    throws Exception
  {
    File dbFile = copyToTemp(srcName);
    byte[] srcPage0 = readPage0(dbFile);

    Database db = new DatabaseBuilder(dbFile).open();
    try {
      if(password != null) {
        PasswordUtil.setDatabasePassword(db, password);
      } else {
        PasswordUtil.removeDatabasePassword(db);
      }
      assertEquals(password, db.getDatabasePassword());
    } finally {
      db.close();
    }

    File expectedFile = new File(DIR + expectedName);

    // the password must read back the same way after a reopen
    assertEquals(password, readPassword(dbFile));

    // the password field must match what ms access wrote
    byte[] page0 = readPage0(dbFile);
    assertArrayEquals(pwdField(readPage0(expectedFile)), pwdField(page0));

    // and nothing else in page 0 may have moved.  note this is checked
    // against the source file rather than the expected one, since ms access
    // also touches unrelated bytes of page 0 on save
    assertArrayEquals(clearPwdField(srcPage0), clearPwdField(page0));

    // every masked SID must match what ms access wrote
    assertEquals(readSids(expectedFile), readSids(dbFile));
  }

  private void doTestUnsupportedFormat(Database db) throws Exception
  {
    try {
      PasswordUtil.setDatabasePassword(db, PWD);
      fail("UnsupportedOperationException should have been thrown");
    } catch(UnsupportedOperationException e) {
      // success
    }

    try {
      PasswordUtil.removeDatabasePassword(db);
      fail("UnsupportedOperationException should have been thrown");
    } catch(UnsupportedOperationException e) {
      // success
    }
  }

  private static File copyToTemp(String name) throws IOException
  {
    return copyToTemp(name, ".mdb");
  }

  private static File copyToTemp(String name, String ext) throws IOException
  {
    File dbFile = File.createTempFile("pwdtest", ext);
    dbFile.deleteOnExit();
    Files.copy(new File(DIR + name).toPath(), dbFile.toPath(),
               StandardCopyOption.REPLACE_EXISTING);
    return dbFile;
  }

  private static byte[] readPage0(File dbFile) throws IOException
  {
    byte[] page0 = new byte[PAGE_SIZE];
    InputStream istream = Files.newInputStream(dbFile.toPath());
    try {
      int pos = 0;
      while(pos < page0.length) {
        int read = istream.read(page0, pos, (page0.length - pos));
        if(read < 0) {
          throw new IOException("could not read page 0 of " + dbFile);
        }
        pos += read;
      }
    } finally {
      istream.close();
    }
    return page0;
  }

  private static byte[] pwdField(byte[] page0)
  {
    return Arrays.copyOfRange(page0, OFF_PWD, (OFF_PWD + LEN_PWD));
  }

  /**
   * Returns a copy of the given page with the password field zeroed, so two
   * pages can be compared while ignoring it.
   */
  private static byte[] clearPwdField(byte[] page0)
  {
    byte[] cleared = page0.clone();
    Arrays.fill(cleared, OFF_PWD, (OFF_PWD + LEN_PWD), (byte)0);
    return cleared;
  }

  private static String readPassword(File dbFile) throws Exception
  {
    Database db = new DatabaseBuilder(dbFile).setReadOnly(true).open();
    try {
      return db.getDatabasePassword();
    } finally {
      db.close();
    }
  }

  private static List<String> readSids(File dbFile) throws Exception
  {
    Database db = new DatabaseBuilder(dbFile).setReadOnly(true).open();
    try {
      return readSids(db);
    } finally {
      db.close();
    }
  }

  /**
   * Returns every masked SID in the database as hex, sorted, so two databases
   * can be compared without depending on row order.
   */
  private static List<String> readSids(Database db) throws Exception
  {
    List<String> sids = new ArrayList<String>();

    for(String[] sidCol : SID_COLUMNS) {
      Table table = db.getSystemTable(sidCol[0]);
      assertNotNull(table);
      Column column = table.getColumn(sidCol[1]);

      for(Row row : table) {
        byte[] sid = (byte[])row.get(column.getName());
        if((sid == null) || (sid.length == 0)) {
          continue;
        }
        sids.add(sidCol[0] + ":" + toHex(sid));
      }
    }

    assertFalse(sids.isEmpty());
    Collections.sort(sids);
    return sids;
  }

  private static String toHex(byte[] bytes)
  {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for(byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }

  private static String createString(int len)
  {
    StringBuilder sb = new StringBuilder(len);
    for(int i = 0; i < len; ++i) {
      sb.append((char)('a' + (i % 26)));
    }
    return sb.toString();
  }
}
