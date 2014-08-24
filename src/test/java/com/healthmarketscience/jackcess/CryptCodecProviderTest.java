/*
Copyright (c) 2010 James Ahlborn

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


import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.healthmarketscience.jackcess.Row;
import com.healthmarketscience.jackcess.impl.DatabaseImpl;
import static org.junit.Assert.*;
import org.junit.Test;


/**
 *
 * @author James Ahlborn
 */
public class CryptCodecProviderTest 
{

  @Test
  public void testMSISAM() throws Exception
  {
    try {
      new DatabaseBuilder(new File("src/test/data/money2001.mny"))
        .setReadOnly(true).open();
      fail("UnsupportedOperationException should have been thrown");
    } catch(UnsupportedOperationException e) {
      // success
    }

    Database db = open("src/test/data/money2001.mny", true, null);

    doCheckMSISAM2001Db(db);

    db.close();

    db = open("src/test/data/money2001-pwd.mny", true, null);

    doCheckMSISAM2001Db(db);

    db.close();

    db = open("src/test/data/money2002.mny", true, null);

    doCheckMSISAM2002Db(db);

    db.close();

    db = open("src/test/data/money2008.mny", true, null);

    doCheckMSISAM2008Db(db);

    db.close();

    try {
      open("src/test/data/money2008-pwd.mny", true, null);
      fail("IllegalStateException should have been thrown");
    } catch(IllegalStateException e) {
      // success
      assertEquals("Incorrect password provided", e.getMessage());
    }

    try {
      open("src/test/data/money2008-pwd.mny", true, "WrongPassword");
      fail("IllegalStateException should have been thrown");
    } catch(IllegalStateException e) {
      // success
      assertEquals("Incorrect password provided", e.getMessage());
    }

    db = open("src/test/data/money2008-pwd.mny", true, "Test12345");

    doCheckMSISAM2008Db(db);

    db.close();    
  }

  @Test
  public void testReadJet() throws Exception
  {
    try {
      new DatabaseBuilder(new File("src/test/data/db-enc.mdb")).setReadOnly(true)
        .open();
      fail("UnsupportedOperationException should have been thrown");
    } catch(UnsupportedOperationException e) {
      // success
    }


    Database db = open("src/test/data/db-enc.mdb", true, null);

    assertEquals(Database.FileFormat.V2000, db.getFileFormat());

    doCheckJetDb(db, 0);

    db.close();

    db = open("src/test/data/db97-enc.mdb", true, null);

    assertEquals(Database.FileFormat.V1997, db.getFileFormat());

    doCheckJetDb(db, 0);

    db.close();
  }

  @Test
  public void testWriteJet() throws Exception
  {
    Database db = openCopy("src/test/data/db-enc.mdb", null);

    Table t = db.getTable("Table1");
    
    ((DatabaseImpl)db).getPageChannel().startWrite();
    try {
      for(int i = 0; i < 1000; ++i) {
        t.addRow(null, "this is the value of col1 " + i, i);
      }
    } finally {
      ((DatabaseImpl)db).getPageChannel().finishWrite();
    }

    db.flush();

    doCheckJetDb(db, 1000);

    db.close();
  }
  
  @Test
  public void testReadOfficeEnc() throws Exception
  {
    for(String fname : Arrays.asList("src/test/data/db2007-oldenc.accdb",
                                     "src/test/data/db2007-enc.accdb")) {
      try {
        new DatabaseBuilder(new File(fname)).setReadOnly(true).open();
        fail("UnsupportedOperationException should have been thrown");
      } catch(UnsupportedOperationException e) {
        // success
      }

      try {
        open(fname, true, null);
        fail("IllegalStateException should have been thrown");
      } catch(IllegalStateException e) {
        // success
        assertEquals("Incorrect password provided", e.getMessage());
      }

      try {
        open(fname, true, "WrongPassword");
        fail("IllegalStateException should have been thrown");
      } catch(IllegalStateException e) {
        // success
        assertEquals("Incorrect password provided", e.getMessage());
      }

      Database db = open(fname, true, "Test123");

      db.getSystemTable("MSysQueries");
      doCheckOfficeDb(db, 0);

      db.close();

      db = open("src/test/data/db2013-enc.accdb", true, "1234");

      db.getSystemTable("MSysQueries");
      doCheckOffice2013Db(db, 0);

      db.close();
    }
  }

  @Test
  public void testWriteOfficeEnc() throws Exception
  {

    for(String fname : Arrays.asList("src/test/data/db2007-oldenc.accdb",
                                     "src/test/data/db2007-enc.accdb")) {
      Database db = openCopy(fname, "Test123");

      Table t = db.getTable("Table1");
    
      ((DatabaseImpl)db).getPageChannel().startWrite();
      try {
        for(int i = 0; i < 1000; ++i) {
          t.addRow(null, "this is the value of col1 " + i);
        }
      } finally {
        ((DatabaseImpl)db).getPageChannel().finishWrite();
      }

      db.flush();

      doCheckOfficeDb(db, 1000);      
      
      db.close();
    } 
  }

  @Test
  public void testPasswordCallback() throws Exception
  {
    final AtomicInteger _count = new AtomicInteger();
    PasswordCallback pc = new PasswordCallback() {
      public String getPassword() {
        _count.incrementAndGet();
        return "Test123";
      }
    };

    Database db = new DatabaseBuilder(new File("src/test/data/db-enc.mdb"))
      .setReadOnly(true)
      .setCodecProvider(new CryptCodecProvider().setPasswordCallback(pc))
      .open();

    Table t = db.getTable("Table1");
    assertNotNull(t);

    assertEquals(0, _count.get());

    db = new DatabaseBuilder(
        new File("src/test/data/db2007-enc.accdb"))
      .setReadOnly(true)
      .setCodecProvider(new CryptCodecProvider().setPasswordCallback(pc))
      .open();
    
    t = db.getTable("Table1");
    assertNotNull(t);

    assertEquals(1, _count.get());
  }
  
  private static void doCheckJetDb(Database db, int addedRows) throws Exception
  {
    Table t = db.getTable("Table1");

    List<Row> expectedRows = 
      DatabaseTest.createExpectedTable(
          DatabaseTest.createExpectedRow(
              "ID", 1,
              "col1", "hello",
              "col2", 0),
          DatabaseTest.createExpectedRow(
              "ID", 2,
              "col1", "world",
              "col2", 42));

    if(addedRows > 0) {
      expectedRows = new ArrayList<Row>(expectedRows);
      int nextId = 3;
      for(int i = 0; i < addedRows; ++i) {
        expectedRows.add(DatabaseTest.createExpectedRow(
                             "ID", nextId++,
                             "col1", "this is the value of col1 " + i,
                             "col2", i));
      }
    }
    
    DatabaseTest.assertTable(expectedRows, t);
  }

  private static void doCheckOfficeDb(Database db, int addedRows) throws Exception
  {
    Table t = db.getTable("Table1");

    List<Row> expectedRows = 
      DatabaseTest.createExpectedTable(
          DatabaseTest.createExpectedRow(
              "ID", 1,
              "Field1", "foo"));

    if(addedRows > 0) {
      expectedRows = new ArrayList<Row>(expectedRows);
      int nextId = 2;
      for(int i = 0; i < addedRows; ++i) {
        expectedRows.add(DatabaseTest.createExpectedRow(
                             "ID", nextId++,
                             "Field1", "this is the value of col1 " + i));
      }
    }
    
    DatabaseTest.assertTable(expectedRows, t);
  }

  private static void doCheckOffice2013Db(Database db, int addedRows) throws Exception
  {
    Table t = db.getTable("Customers");

    List<Row> expectedRows = 
      DatabaseTest.createExpectedTable(
          DatabaseTest.createExpectedRow(
              "ID", 1,
              "Field1", "Test"),
          DatabaseTest.createExpectedRow(
              "ID", 2,
              "Field1", "Test2"),
          DatabaseTest.createExpectedRow(
              "ID", 3,
              "Field1", "a"),
          DatabaseTest.createExpectedRow(
              "ID", 4,
              "Field1", null),
          DatabaseTest.createExpectedRow(
              "ID", 5,
              "Field1", "c"),
          DatabaseTest.createExpectedRow(
              "ID", 6,
              "Field1", "d"),
          DatabaseTest.createExpectedRow(
              "ID", 7,
              "Field1", "f"));

    if(addedRows > 0) {
      expectedRows = new ArrayList<Row>(expectedRows);
      int nextId = 2;
      for(int i = 0; i < addedRows; ++i) {
        expectedRows.add(DatabaseTest.createExpectedRow(
                             "ID", nextId++,
                             "Field1", "this is the value of col1 " + i));
      }
    }
    
    DatabaseTest.assertTable(expectedRows, t);
  }

  private static void doCheckMSISAM2001Db(Database db) throws Exception
  {
    assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

    assertEquals(Arrays.asList("ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "FI", "Goal Custom Pool", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC", "PAY", "PGM", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "VIEW", "Worksheet Custom Pool", "XACCT", "XMAPACCT", "XMAPSAT", "XPAY"), 
                 new ArrayList<String>(db.getTableNames()));

    Table t = db.getTable("CRNC");

    Set<String> cols = new HashSet<String>(
        Arrays.asList("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol"));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 1, "szName", "Argentinean peso", 
                     "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"),
                 t.getDefaultCursor().getNextRow(cols));
                 
    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 2, "szName", "Australian dollar", 
                     "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"),
                 t.getDefaultCursor().getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 3, "szName", "Austrian schilling", 
                     "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"),
                 t.getDefaultCursor().getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 4, "szName", "Belgian franc", "lcid", 2060,
                     "szIsoCode", "BEF", "szSymbol", "/BECUS"),
                 t.getDefaultCursor().getNextRow(cols));
  }

  private static void doCheckMSISAM2002Db(Database db) throws Exception
  {
    assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

    assertEquals(Arrays.asList("ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "BILL", "BILL_FLD", "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "FI", "Goal Custom Pool", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC", "PAY", "PGM", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "UIE", "UKSavings", "UKWiz", "UKWizAddress", "UKWizCompanyCar", "UKWizLoan", "UKWizMortgage", "UKWizPenScheme", "UKWizPension", "UKWizWillExecutor", "UKWizWillGift", "UKWizWillGuardian", "UKWizWillLovedOne", "UKWizWillMaker", "UKWizWillPerson", "UKWizWillResidue", "UNOTE", "VIEW", "Worksheet Custom Pool", "XACCT", "XBAG", "XMAPACCT", "XMAPSAT", "XPAY"), 
                 new ArrayList<String>(db.getTableNames()));

    Table t = db.getTable("CRNC");

    Set<String> cols = new HashSet<String>(
        Arrays.asList("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol"));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 1, "szName", "Argentinian peso", 
                     "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"),
                 t.getDefaultCursor().getNextRow(cols));
                 
    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 2, "szName", "Australian dollar", 
                     "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"),
                 t.getDefaultCursor().getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 3, "szName", "Austrian schilling", 
                     "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"),
                 t.getDefaultCursor().getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 4, "szName", "Belgian franc", "lcid", 2060,
                     "szIsoCode", "BEF", "szSymbol", "/BECUS"),
                 t.getDefaultCursor().getNextRow(cols));
  }

  private static void doCheckMSISAM2008Db(Database db) throws Exception
  {
    assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

    assertEquals(Arrays.asList("ACCT", "ADDR", "ADV", "ADV_SUM", "Advisor Important Dates Custom Pool", "Asset Allocation Custom Pool", "AUTO", "AWD", "BGT", "BGT_BKT", "BGT_ITM", "BILL", "BILL_FLD", "CAT", "CESRC", "CLI", "CLI_DAT", "CNTRY", "CRIT", "CRNC", "CRNC_EXCHG", "CT", "DHD", "Feature Expiration Custom Pool", "FI", "Inventory Custom Pool", "ITM", "IVTY", "LOT", "LSTEP", "MAIL", "MCSRC", "PAY", "PGM", "PM_RPT", "PMT", "PORT_REC", "Portfolio View Custom Pool", "POS_STMT", "PREF", "PREF_LIST", "PRODUCT", "PROJ", "PROV_FI", "PROV_FI_PAY", "Report Custom Pool", "SAV_GOAL", "SCHE_TASK", "SEC", "SEC_SPLIT", "SIC", "SOQ", "SP", "STMT", "SVC", "Tax Rate Custom Pool", "Tax Scenario Custom Pool", "TAXLINE", "TMI", "TRIP", "TRN", "TRN_INV", "TRN_INVOICE", "TRN_OL", "TRN_SPLIT", "TRN_XFER", "TXSRC", "UI_VIEW", "UIE", "UNOTE", "VIEW", "Worksheet Custom Pool", "X_FMLA", "X_ITM", "X_META_REF", "X_PARM", "XACCT", "XBAG", "XMAPACCT", "XMAPSAT", "XMAPSEC", "XPAY", "XSYNCCHUNK"), 
                 new ArrayList<String>(db.getTableNames()));

    Table t = db.getTable("CRNC");

    Set<String> cols = new HashSet<String>(
        Arrays.asList("hcrnc", "szName", "lcid", "szIsoCode", "szSymbol"));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 1, "szName", "Argentine peso", 
                     "lcid", 11274, "szIsoCode", "ARS", "szSymbol", "/ARSUS"),
                 t.getDefaultCursor().getNextRow(cols));
                 
    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 2, "szName", "Australian dollar", 
                     "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"),
                 t.getDefaultCursor().getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 3, "szName", "Austrian schilling", 
                     "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"),
                 t.getDefaultCursor().getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 4, "szName", "Belgian franc", "lcid", 2060,
                     "szIsoCode", "BEF", "szSymbol", "/BEFUS"),
                 t.getDefaultCursor().getNextRow(cols));
  }

  static Database openCopy(String fileName, String pwd)
    throws Exception
  {
    File copy = DatabaseTest.createTempFile(false);
    DatabaseTest.copyFile(new File(fileName), copy);
    return open(copy.getPath(), false, pwd);
  }

  static Database open(String fileName, boolean readOnly, String pwd)
    throws Exception
  {
    return new DatabaseBuilder(new File(fileName))
      .setReadOnly(readOnly)
      .setCodecProvider(new CryptCodecProvider(pwd))
      .open();
  }

  static void checkCryptoStrength()
  {
    boolean unlimitedCrypto = false;
    try {
      unlimitedCrypto = (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") > 256);
    } catch(Exception e) {}    
    System.out.println("Unlimited strength cryptography: " + unlimitedCrypto);    
  }
}
