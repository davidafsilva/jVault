package pt.davidafsilva.jvault.model;

/*
 * #%L
 * jVault
 * %%
 * Copyright (C) 2014 David Silva
 * %%
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 
 * 3. Neither the name of the David Silva nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * #L%
 */

import java.time.Instant;

/**
 * This entity represents a secured {@link Entry}, in which the {@link #getValue() value} is
 * cryptographically secured by a {@link pt.davidafsilva.jvault.vault.Vault}.
 *
 * This class is immutable, therefore it inherits it's thread-safe nature.
 *
 * @author David Silva
 */
public final class SecureEntry extends AbstractEntry {

  /**
   * Creates a new secured entry
   *
   * @param timestamp the entry's creation timestamp
   * @param key       the original key
   * @param value     the secure value
   */
  private SecureEntry(final long timestamp, final String key, final String value) {
    super(timestamp, key, value);
  }

  /**
   * Static factory method for the creation of an {@link SecureEntry}.
   *
   * @param key   the original key
   * @param value the ciphered value
   * @return an secure entry with the given key-value pair
   */
  public static SecureEntry of(final String key, final String value) {
    return new SecureEntry(Instant.now().toEpochMilli(), key, value);
  }
}
