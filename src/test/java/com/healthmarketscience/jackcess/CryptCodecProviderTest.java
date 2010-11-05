// Copyright (c) 2010 Boomi, Inc.

package com.healthmarketscience.jackcess;


import java.io.File;
import java.io.PrintWriter;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
    {
      File f = new File("/data2/jackcess_test/db2.mdb");
      Database db = Database.open(f, true);
      System.out.println("FOO " + f);
      dumpDbHeader(db);
      db.close();
    }

    File f = new File("/data2/jackcess_test/blankwithpass.mny");
//     File f = new File("/data2/jackcess_test/blank.mny");
//     File f = new File("/data2/jackcess_test/Test-nopwd.mny");
    Database db = Database.open(f, true, true, null, null, 
                                new CryptCodecProvider("Test12345"));

    assertEquals(Database.FileFormat.MSISAM, db.getFileFormat());

    db.close();
  }

//   @Test
  public void testJet() throws Exception
  {
    File f = new File("/data2/jackcess_test/dbenc.mdb");
    Database db = Database.open(f, true, true, null, null, 
                                new CryptCodecProvider());

    assertEquals(Database.FileFormat.V2000, db.getFileFormat());

    dumpDatabase(db);

    db.close();
  }

  private static void dumpDbHeader(Database db) throws Exception
  {
    PageChannel channel = db.getPageChannel();

    ByteBuffer buffer = channel.createPageBuffer();
    channel.readPage(buffer, 0);

    byte[] header = new byte[0x98];
    buffer.position(0);
    buffer.get(header);

    System.out.println("FOO db header: \n" + ByteUtil.toHexString(header));
  }

  static void dumpDatabase(Database mdb) throws Exception {
    dumpDatabase(mdb, new PrintWriter(System.out, true));
  }

  static void dumpTable(Table table) throws Exception {
    dumpTable(table, new PrintWriter(System.out, true));
  }

  static void dumpDatabase(Database mdb, PrintWriter writer) throws Exception {
    writer.println("DATABASE:");
    for(Table table : mdb) {
      dumpTable(table, writer);
    }
  }

  static void dumpTable(Table table, PrintWriter writer) throws Exception {
    // make sure all indexes are read
    for(Index index : table.getIndexes()) {
      index.initialize();
    }
    
    writer.println("TABLE: " + table.getName());
    List<String> colNames = new ArrayList<String>();
    for(Column col : table.getColumns()) {
      colNames.add(col.getName());
    }
    writer.println("COLUMNS: " + colNames);
    for(Map<String, Object> row : Cursor.createCursor(table)) {

      // make byte[] printable
      for(Map.Entry<String, Object> entry : row.entrySet()) {
        Object v = entry.getValue();
        if(v instanceof byte[]) {
          byte[] bv = (byte[])v;
          entry.setValue(ByteUtil.toHexString(ByteBuffer.wrap(bv), bv.length));
        }
      }
      
      writer.println(row);
    }
  }

}
