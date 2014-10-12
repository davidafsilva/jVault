package pt.davidafsilva.jvault;

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
