package pt.davidafsilva.jvault;

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

import java.util.Collection;
import java.util.Optional;

/**
 * The secure vault definition.
 *
 * @author David Silva
 */
public interface Vault {

  /**
   * Reads all of the stored entries from the vault.
   *
   * @return the stored entries, an empty collection is returned when nothing is stored.
   * @see #read(String)
   */
  Collection<SecureEntry> read();

  /**
   * Reads the entry stored in the vault with the given {@code key}.
   *
   * @param key the key for the entry
   * @return the entry associated with the given {@code key}, or none if there's no such mapping.
   * @see #read()
   * @see Optional
   */
  Optional<SecureEntry> read(final String key);

  /**
   * Writes the given key-value pair to the vault
   *
   * @param entry the unsecure entry
   * @return the secure entry for the given key-value pair
   * @throws VaultOperationException if an error occurs while ciphering the entry
   */
  SecureEntry write(final UnsecureEntry entry) throws VaultOperationException;

  /**
   * Deletes the entry stored in the vault with the given {@code key}.
   *
   * @param key the key for the entry
   * @return the deleted entry, or none if there's no such mapping.
   * @see Optional
   */
  Optional<SecureEntry> delete(final String key);

  /**
   * Translate the secured entry and returns the original (unsecured) entry
   *
   * @param entry the entry to be translated
   * @return the original value
   * @throws IllegalArgumentException if the given entry is not in the vault
   * @throws VaultOperationException  if an error occurs while deciphering the entry
   * @see #write(UnsecureEntry)
   */
  UnsecureEntry translate(final SecureEntry entry) throws VaultOperationException;
}
