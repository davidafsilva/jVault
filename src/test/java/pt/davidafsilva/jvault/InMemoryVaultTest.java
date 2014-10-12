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

import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.util.Collection;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for the in-memory implementation of the vault
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class InMemoryVaultTest {

  // the vault
  private static Vault vault;

  @BeforeClass
  public static void setup() throws VaultInitializationException {
    vault = new InMemoryVault("12345678901234567890123456789012", "12345678", 1024, 128);
  }

  @Test
  public void test_1_read_noElements() {
    assertTrue(vault.read().isEmpty());
  }

  @Test
  public void test_2_read_invalidKey() {
    assertFalse(vault.read("key").isPresent());
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_3_translateEntryNotInVault() throws VaultOperationException {
    vault.translate(SecureEntry.of("k", "k"));
  }

  @Test
  public void test_4_write() throws VaultOperationException {
    // write
    final SecureEntry secureEntry = vault.write(UnsecureEntry.of("key1", "dummy"));
    assertNotNull(secureEntry);
    assertEquals("key1", secureEntry.getKey());
    assertNotNull(secureEntry.getValue());
    // read with key
    final Optional<SecureEntry> secureEntryOptional = vault.read(secureEntry.getKey());
    assertTrue(secureEntryOptional.isPresent());
    assertEquals(secureEntry, secureEntryOptional.get());
    // translate
    final UnsecureEntry unsecureEntry = vault.translate(secureEntry);
    assertNotNull(unsecureEntry);
    assertEquals("key1", unsecureEntry.getKey());
    assertEquals("dummy", unsecureEntry.getValue());
  }

  @Test
  public void test_5_read() throws VaultOperationException {
    // read all of the secure entries
    final Collection<SecureEntry> secureEntries = vault.read();
    assertEquals(1, secureEntries.size());
    assertEquals("key1", secureEntries.iterator().next().getKey());
  }

  @Test
  public void test_6_delete() throws VaultOperationException {
    // delete entry
    final Optional<SecureEntry> secureEntryOptional = vault.delete("key1");
    assertTrue(secureEntryOptional.isPresent());
    // check that the vault is really empty
    assertTrue(vault.read().isEmpty());
    assertFalse(vault.read("key1").isPresent());
  }

  @Test
  public void test_7_writeTwo() throws VaultOperationException {
    // write
    final SecureEntry secureEntry1 = vault.write(UnsecureEntry.of("key1", "dummy1"));
    final SecureEntry secureEntry2 = vault.write(UnsecureEntry.of("key2", "dummy2"));
    assertNotNull(secureEntry1);
    assertNotNull(secureEntry2);
    assertEquals(2, vault.read().size());
    assertEquals(secureEntry1, vault.read(secureEntry1.getKey()).get());
    assertEquals(secureEntry2, vault.read(secureEntry2.getKey()).get());
  }
}
