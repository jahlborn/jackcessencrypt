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

package com.healthmarketscience.jackcess.crypt.impl;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.healthmarketscience.jackcess.Column;
import com.healthmarketscience.jackcess.Database;
import com.healthmarketscience.jackcess.Row;
import com.healthmarketscience.jackcess.Table;
import com.healthmarketscience.jackcess.crypt.util.StreamCipherCompat;
import com.healthmarketscience.jackcess.crypt.util.StreamCipherFactory;
import com.healthmarketscience.jackcess.impl.ByteUtil;
import com.healthmarketscience.jackcess.impl.DatabaseImpl;
import com.healthmarketscience.jackcess.impl.JetFormat;
import com.healthmarketscience.jackcess.impl.PageChannel;
import org.bouncycastle.crypto.params.KeyParameter;


/**
 * Adds, changes and removes the database password on a jet 4 database.
 * <p>
 * Two pieces of state have to agree.  The password field in page 0 is what
 * makes ms access prompt for a password, and every SID stored in the database
 * is masked with an rc4 keystream whose key is folded out of page 0, the
 * password field included.  Writing only the password field produces a
 * database which ms access prompts for and then refuses to open, reporting
 * that the user does not have permission.
 * <p>
 * So changing the password means re-masking every SID under the new key.  The
 * plaintext SIDs never have to be known: xor-ing out the old keystream and in
 * the new one converts a stored value directly, which also means this works
 * for a database created under any workgroup file.
 *
 * @author James Ahlborn
 */
public class JetPasswordHandler
{
  /** the SID columns which have to be re-masked, table name to column name */
  private static final Map<String,String> SID_COLUMNS = new LinkedHashMap<>();
  static {
    SID_COLUMNS.put("MSysACEs", "SID");
    SID_COLUMNS.put("MSysObjects", "Owner");
  }

  /** the fold which builds the SID key wraps its shift at this bit */
  private static final int SID_KEY_SHIFT_MODULUS = 24;

  /** the SID key is used as this many little-endian bytes of rc4 key */
  private static final int SID_KEY_LENGTH = 4;

  private final DatabaseImpl _db;
  private final PageChannel _pageChannel;
  private final JetFormat _format;

  public JetPasswordHandler(Database db) {
    _db = (DatabaseImpl)db;
    _pageChannel = _db.getPageChannel();
    _format = _pageChannel.getFormat();
  }

  /**
   * Sets the database password, or removes it if the given password is
   * {@code null} or empty.
   */
  public void setPassword(String password) throws IOException
  {
    validatePasswordChange();

    // encode the password up front, so an unusable one is rejected before
    // anything is read or written
    byte[] newField = createPasswordField(password);

    // make sure nothing is still pending behind the changes below
    _db.flush();

    ByteBuffer headerPage = BaseCryptCodecHandler.readHeaderPage(_pageChannel);

    byte[] oldField = readPasswordField(headerPage);
    int oldKey = createSidKey(headerPage);

    writePasswordField(headerPage, newField);

    if(Arrays.equals(oldField, readPasswordField(headerPage))) {
      // the database already has this password, nothing to do
      return;
    }

    int newKey = createSidKey(headerPage);

    _pageChannel.startWrite();
    try {

      // the SIDs are rewritten before page 0 so that a failure part way
      // through leaves the password field describing the key the database
      // started with.  note that this operation is not atomic either way, see
      // the PasswordUtil documentation
      remaskSids(oldKey, newKey);

      _pageChannel.writePage(headerPage, 0);

    } finally {
      _pageChannel.finishWrite();
    }

    _db.flush();
  }

  private void validatePasswordChange()
  {
    if(_db.isReadOnly()) {
      throw new IllegalStateException(
          "Database is read-only, cannot modify the database password");
    }

    if(_format != JetFormat.VERSION_4) {
      throw new UnsupportedOperationException(
          "Modifying the database password is only supported for jet 4 " +
          "databases, not " + _format);
    }
  }

  /**
   * Returns the contents of the password field for the given password, before
   * the creation date mask is applied.  A {@code null} or empty password
   * gives the empty field which indicates no password.
   */
  private byte[] createPasswordField(String password)
  {
    byte[] field = new byte[_format.SIZE_PASSWORD];

    if(password != null) {
      ByteBuffer encoded = _db.getCharset().encode(password);
      int len = encoded.remaining();
      if(len > field.length) {
        throw new IllegalArgumentException(
            "Password encodes to " + len + " bytes, which is longer than " +
            "the maximum of " + field.length);
      }
      encoded.get(field, 0, len);
    }

    return field;
  }

  /**
   * Folds the 32-bit key which masks every SID in the database out of the
   * given header page.  The fold walks the even bytes of the password region,
   * which are the low bytes of the utf-16 password, over a value seeded from
   * the database creation date.  The region runs past the password field and
   * takes in the creation date a second time, which is why the key changes
   * with the creation date even when there is no password at all.
   */
  private int createSidKey(ByteBuffer headerPage)
  {
    byte[] region = BaseCryptCodecHandler.readPasswordRegion(headerPage,
                                                             _format);

    int key = ByteUtil.getInt(headerPage, _format.OFFSET_HEADER_DATE,
                              ByteOrder.LITTLE_ENDIAN);

    for(int i = 0; i < _format.SIZE_PASSWORD; ++i) {
      key ^= (region[i * 2] & 0xFF) << (i % SID_KEY_SHIFT_MODULUS);
    }

    return key;
  }

  private byte[] readPasswordField(ByteBuffer headerPage)
  {
    return ByteUtil.getBytes(headerPage, _format.OFFSET_PASSWORD,
                             _format.SIZE_PASSWORD);
  }

  /**
   * Writes the given password field into the given header page, masked the way
   * the database expects it.
   */
  private void writePasswordField(ByteBuffer headerPage, byte[] field)
  {
    // the field carries an additional mask generated from the database
    // creation date
    byte[] pwdMask = DatabaseImpl.getPasswordMask(headerPage, _format);
    if(pwdMask != null) {
      field = field.clone();
      for(int i = 0; i < field.length; ++i) {
        field[i] ^= pwdMask[i % pwdMask.length];
      }
    }

    for(int i = 0; i < field.length; ++i) {
      headerPage.put((_format.OFFSET_PASSWORD + i), field[i]);
    }
  }

  /**
   * Converts every SID in the database from the old key to the new one.
   */
  private void remaskSids(int oldKey, int newKey) throws IOException
  {
    RemaskPad pad = new RemaskPad(oldKey, newKey);

    for(Map.Entry<String,String> sidCol : SID_COLUMNS.entrySet()) {

      Table table = _db.getSystemTable(sidCol.getKey());
      if(table == null) {
        continue;
      }

      Column column = findColumn(table, sidCol.getValue());
      if(column == null) {
        continue;
      }
      String colName = column.getName();

      // read the rows before modifying any of them
      List<Row> rows = new ArrayList<>();
      for(Row row : table) {
        rows.add(row);
      }

      for(Row row : rows) {
        byte[] sid = (byte[])row.get(colName);
        if((sid == null) || (sid.length == 0)) {
          continue;
        }
        pad.apply(sid);
        row.put(colName, sid);
        table.updateRow(row);
      }
    }
  }

  private static Column findColumn(Table table, String colName)
  {
    for(Column column : table.getColumns()) {
      if(colName.equalsIgnoreCase(column.getName())) {
        return column;
      }
    }
    return null;
  }

  /**
   * Returns the first len bytes of the rc4 keystream for the given key.
   */
  private static byte[] createKeystream(int key, int len)
  {
    byte[] keyBytes = new byte[SID_KEY_LENGTH];
    PageChannel.wrap(keyBytes).putInt(key);

    StreamCipherCompat cipher = StreamCipherFactory.newRC4Engine();
    cipher.init(BaseCryptCodecHandler.CIPHER_DECRYPT_MODE,
                new KeyParameter(keyBytes));

    // running the cipher over zeroes yields the keystream itself
    byte[] keystream = new byte[len];
    cipher.processStreamBytes(new byte[len], 0, len, keystream, 0);
    return keystream;
  }

  /**
   * The xor pad which converts a SID masked with the old key into the same SID
   * masked with the new one.  It is the xor of the two keystreams, both of
   * which start at the beginning for every SID regardless of length, so
   * applying it never materializes a plaintext SID.
   */
  private static final class RemaskPad
  {
    private final int _oldKey;
    private final int _newKey;
    private byte[] _pad = new byte[0];

    private RemaskPad(int oldKey, int newKey) {
      _oldKey = oldKey;
      _newKey = newKey;
    }

    private void apply(byte[] sid) {
      ensureLength(sid.length);
      for(int i = 0; i < sid.length; ++i) {
        sid[i] ^= _pad[i];
      }
    }

    private void ensureLength(int len) {
      if(_pad.length >= len) {
        return;
      }

      byte[] pad = createKeystream(_oldKey, len);
      byte[] newKeystream = createKeystream(_newKey, len);
      for(int i = 0; i < len; ++i) {
        pad[i] ^= newKeystream[i];
      }
      _pad = pad;
    }
  }
}
