package pt.davidafsilva.jvault.vault;

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

import org.junit.AfterClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import pt.davidafsilva.jvault.model.SecureEntry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit test for the file based implementations of the vault
 *
 * @author David Silva
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public abstract class FileVaultTest extends VaultTester<FileVault> {

  // the vault
  private static FileVault vault;

  // the current vault file
  private static Path vaultFile;

  @Override
  FileVault getVault() {
    if (vault == null) {
      try {
        vaultFile = Files.createTempFile("pt.davidafsilva.jvault.", ".vault");
        vaultFile.toFile().deleteOnExit();
        vault = createVault(vaultFile);
      } catch (final IOException | VaultInitializationException e) {
        e.printStackTrace();
        fail(e.getMessage());
      }
    }
    return vault;
  }

  /**
   * Creates a new file vault for the specified path
   *
   * @param path the path of the vault
   * @return the file vault instance
   */
  abstract FileVault createVault(final Path path) throws VaultInitializationException;

  @Test
  public void test_i_persist() throws VaultOperationException, IOException {
    vault.persist();
    final long lastModified = vaultFile.toFile().lastModified();
    vault.persist();
    assertEquals(lastModified, vaultFile.toFile().lastModified());
  }

  @Test
  public void test_j_load() throws VaultInitializationException, VaultOperationException {
    vault = createVault(vaultFile);
    assertEquals(2, vault.read().size());
    final Optional<SecureEntry> entry1 = vault.read("key1");
    final Optional<SecureEntry> entry2 = vault.read("key2");
    assertTrue(entry1.isPresent());
    assertTrue(entry2.isPresent());
    assertEquals("dummy1", vault.translate(entry1.get()).getValue());
    assertEquals("dummy2", vault.translate(entry2.get()).getValue());
  }

  @Test(expected = VaultCorruptedException.class)
  public void test_k_loadCorruption() throws IOException, VaultInitializationException {
    // mess the file contents - a single byte is enough
    try (final Writer w = new FileWriter(vaultFile.toFile(), true)) {
      w.write(0x00);
      w.flush();
    }
    vault = createVault(vaultFile);
  }

  @AfterClass
  public static void cleanUp() {
    vault = null;
    vaultFile = null;
  }
}
