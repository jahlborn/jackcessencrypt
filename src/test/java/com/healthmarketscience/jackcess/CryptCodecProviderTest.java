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

import org.junit.Test;

import static org.junit.Assert.*;


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
      Database.open(new File("src/test/data/money2001.mny"), true);
      fail("UnsupportedOperationException should have been thrown");
    } catch(UnsupportedOperationException e) {
      // success
    }

    Database db = Database.open(new File("src/test/data/money2001.mny"),
                                true, true, null, null, 
                                new CryptCodecProvider());

    doCheckMSISAM2001Db(db);

    db.close();

    db = Database.open(new File("src/test/data/money2001-pwd.mny"),
                       true, true, null, null, 
                       new CryptCodecProvider());

    doCheckMSISAM2001Db(db);

    db.close();

    db = Database.open(new File("src/test/data/money2008.mny"),
                       true, true, null, null, 
                       new CryptCodecProvider());

    doCheckMSISAM2008Db(db);

    db.close();

    try {
      Database.open(new File("src/test/data/money2008-pwd.mny"),
                    true, true, null, null, 
                    new CryptCodecProvider());
      fail("IllegalStateException should have been thrown");
    } catch(IllegalStateException e) {
      // success
    }

    db = Database.open(new File("src/test/data/money2008-pwd.mny"),
                       true, true, null, null, 
                       new CryptCodecProvider("Test12345"));

    doCheckMSISAM2008Db(db);

    db.close();    
  }

  @Test
  public void testJet() throws Exception
  {
    try {
      Database.open(new File("src/test/data/db-enc.mdb"), true);
      fail("UnsupportedOperationException should have been thrown");
    } catch(UnsupportedOperationException e) {
      // success
    }


    Database db = Database.open(new File("src/test/data/db-enc.mdb"),
                                true, true, null, null, 
                                new CryptCodecProvider());

    assertEquals(Database.FileFormat.V2000, db.getFileFormat());

    doCheckJetDb(db);

    db.close();

    db = Database.open(new File("src/test/data/db97-enc.mdb"),
                       true, true, null, null, 
                       new CryptCodecProvider());

    assertEquals(Database.FileFormat.V1997, db.getFileFormat());

    doCheckJetDb(db);

    db.close();    
  }

  private void doCheckJetDb(Database db) throws Exception
  {
    Table t = db.getTable("Table1");

    List<Map<String, Object>> expectedRows = 
      DatabaseTest.createExpectedTable(
          DatabaseTest.createExpectedRow(
              "ID", 1,
              "col1", "hello",
              "col2", 0),
          DatabaseTest.createExpectedRow(
              "ID", 2,
              "col1", "world",
              "col2", 42));
    
    DatabaseTest.assertTable(expectedRows, t);
  }

  private void doCheckMSISAM2001Db(Database db) throws Exception
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
                 t.getNextRow(cols));
                 
    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 2, "szName", "Australian dollar", 
                     "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"),
                 t.getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 3, "szName", "Austrian schilling", 
                     "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"),
                 t.getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 4, "szName", "Belgian franc", "lcid", 2060,
                     "szIsoCode", "BEF", "szSymbol", "/BECUS"),
                 t.getNextRow(cols));
  }

  private void doCheckMSISAM2008Db(Database db) throws Exception
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
                 t.getNextRow(cols));
                 
    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 2, "szName", "Australian dollar", 
                     "lcid", 3081, "szIsoCode", "AUD", "szSymbol", "/AUDUS"),
                 t.getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 3, "szName", "Austrian schilling", 
                     "lcid", 3079, "szIsoCode", "ATS", "szSymbol", "/ATSUS"),
                 t.getNextRow(cols));

    assertEquals(DatabaseTest.createExpectedRow(
                     "hcrnc", 4, "szName", "Belgian franc", "lcid", 2060,
                     "szIsoCode", "BEF", "szSymbol", "/BEFUS"),
                 t.getNextRow(cols));
  }

}
