package pt.davidafsilva.jvault.vault;

import org.junit.BeforeClass;
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

/**
 * Unit test for the file based implementation of the vault
 *
 * @author David Silva
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class ByteFileVaultTest extends VaultTester<ByteFileVault> {

  // the vault
  private static ByteFileVault vault;

  // the vault file
  private static Path vaultFile;

  @BeforeClass
  public static void setup() throws IOException, VaultInitializationException {
    vaultFile = Files.createTempFile("pt.davidafsilva.jvault.", ".vault");
    vaultFile.toFile().deleteOnExit();
    System.out.println(vaultFile);
    vault = new ByteFileVault("12345678901234567890123456789012", "12345678", 1024, 128,
                              vaultFile);
  }

  @Override
  ByteFileVault getVault() {
    return vault;
  }

  @Test
  public void test_8_persist() throws VaultOperationException, IOException {
    vault.persist();
    final long lastModified = vaultFile.toFile().lastModified();
    vault.persist();
    assertEquals(lastModified, vaultFile.toFile().lastModified());
  }

  @Test
  public void test_9_load() throws VaultInitializationException, VaultOperationException {
    vault = new ByteFileVault("12345678901234567890123456789012", "12345678", 1024, 128,
                              vaultFile);
    assertEquals(2, vault.read().size());
    final Optional<SecureEntry> entry1 = vault.read("key1");
    final Optional<SecureEntry> entry2 = vault.read("key2");
    assertTrue(entry1.isPresent());
    assertTrue(entry2.isPresent());
    assertEquals("dummy1", vault.translate(entry1.get()).getValue());
    assertEquals("dummy2", vault.translate(entry2.get()).getValue());
  }

  @Test(expected = VaultCorruptedException.class)
  public void test_10_loadCorruption() throws IOException, VaultInitializationException {
    // mess the file contents - a single byte is enough
    try (final Writer w = new FileWriter(vaultFile.toFile(), true)) {
      w.write(0x00);
      w.flush();
    }
    vault = new ByteFileVault("12345678901234567890123456789012", "12345678", 1024, 128, vaultFile);
  }
}
