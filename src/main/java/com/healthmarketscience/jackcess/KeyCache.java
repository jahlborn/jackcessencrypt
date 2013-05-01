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

import java.util.Map;
import java.util.LinkedHashMap;

/**
 *
 * @author James Ahlborn
 */
public abstract class KeyCache<K> 
{
  private static final int MAX_KEY_CACHE_SIZE = 5;

  private final KeyMap<K> _map = new KeyMap<K>();

  protected KeyCache() 
  {
  }

  public K get(int pageNumber) {
    Integer pageNumKey = pageNumber;
    K key = _map.get(pageNumKey);
    if(key == null) {
      key = computeKey(pageNumber);
      _map.put(pageNumKey, key);
    }
    return key;
  }

  protected abstract K computeKey(int pageNumber);


  private static final class KeyMap<K> extends LinkedHashMap<Integer,K>
  {
    private static final long serialVersionUID = 0L;

    private KeyMap() {
      super(16, 0.75f, true);
    }

    @Override
    protected boolean removeEldestEntry(Map.Entry<Integer,K> eldest) {
      return size() > MAX_KEY_CACHE_SIZE;
    }
  }

}
