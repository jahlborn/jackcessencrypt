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

package com.healthmarketscience.jackcess.crypt.impl;

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
