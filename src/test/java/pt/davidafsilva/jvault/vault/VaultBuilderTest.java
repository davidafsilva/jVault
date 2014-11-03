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

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit test for the vaults builder implementation
 *
 * @author David Silva
 */
public class VaultBuilderTest {

  @Test(expected = NullPointerException.class)
  public void test_invalidPassword_str() {
    VaultBuilder.create().password((String) null);
  }

  @Test(expected = NullPointerException.class)
  public void test_invalidPassword_charArray() {
    VaultBuilder.create().password((char[]) null);
  }

  @Test(expected = NullPointerException.class)
  public void test_invalidSalt_str() {
    VaultBuilder.create().salt((String) null);
  }

  @Test(expected = NullPointerException.class)
  public void test_invalidSalt_byteArray() {
    VaultBuilder.create().salt((byte[]) null);
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_invalidIterations() {
    VaultBuilder.create().iterations(-1);
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_invalidKeySize() {
    VaultBuilder.create().keySize(127);
  }

  @Test(expected = NullPointerException.class)
  public void test_invalidFile() {
    VaultBuilder.create().rawFile(null);
  }

  @Test(expected = NullPointerException.class)
  public void test_invalidFile_noReadPermissions() throws IOException {
    final Path path = Files.createTempFile("pt.davidafsilva.jvault.", ".vault");
    assertTrue(path.toFile().setReadable(false));
    VaultBuilder.create().rawFile(null);
  }

  @Test(expected = NullPointerException.class)
  public void test_invalidFile_noWritePermissions() throws IOException {
    final Path path = Files.createTempFile("pt.davidafsilva.jvault.", ".vault");
    assertTrue(path.toFile().setWritable(false));
    VaultBuilder.create().rawFile(null);
  }

  @Test
  public void test_success_inMemory() throws VaultInitializationException {
    final Vault vault = VaultBuilder.create().inMemory().password("abc").salt("123").build();
    assertNotNull(vault);
  }

  @Test
  public void test_success_rawFile() throws VaultInitializationException, IOException {
    final Path path = Files.createTempFile("pt.davidafsilva.jvault.", ".vault");
    final Vault vault = VaultBuilder.create().rawFile(path).password("abc").salt("123").build();
    assertNotNull(vault);
  }

  @Test
  public void test_success_xmlFile() throws VaultInitializationException, IOException {
    final Path path = Files.createTempFile("pt.davidafsilva.jvault.", ".vault");
    final Vault vault = VaultBuilder.create().xmlFile(path).password("abc").salt("123").build();
    assertNotNull(vault);
  }
}
