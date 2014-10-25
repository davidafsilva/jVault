package pt.davidafsilva.jvault.vault;

import org.junit.Test;

import java.util.Collection;
import java.util.Optional;

import pt.davidafsilva.jvault.model.SecureEntry;
import pt.davidafsilva.jvault.model.UnsecureEntry;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * The base class for the vault tests
 *
 * @author David Silva
 */
abstract class VaultTester<T extends Vault> {

  /**
   * Returns the vault to be tested
   *
   * @return the vault instance
   */
  abstract T getVault();

  @Test
  public void test_1_read_noElements() {
    assertTrue(getVault().read().isEmpty());
  }

  @Test
  public void test_2_read_invalidKey() {
    assertFalse(getVault().read("key").isPresent());
  }

  @Test(expected = IllegalArgumentException.class)
  public void test_3_translateEntryNotInVault() throws VaultOperationException {
    getVault().translate(SecureEntry.of("k", "k"));
  }

  @Test
  public void test_4_write() throws VaultOperationException {
    // write
    final SecureEntry secureEntry = getVault().write(UnsecureEntry.of("key1", "dummy"));
    assertNotNull(secureEntry);
    assertEquals("key1", secureEntry.getKey());
    assertNotNull(secureEntry.getValue());
    // read with key
    final Optional<SecureEntry> secureEntryOptional = getVault().read(secureEntry.getKey());
    assertTrue(secureEntryOptional.isPresent());
    assertEquals(secureEntry, secureEntryOptional.get());
    // translate
    final UnsecureEntry unsecureEntry = getVault().translate(secureEntry);
    assertNotNull(unsecureEntry);
    assertEquals("key1", unsecureEntry.getKey());
    assertEquals("dummy", unsecureEntry.getValue());
  }

  @Test
  public void test_5_read() throws VaultOperationException {
    // read all of the secure entries
    final Collection<SecureEntry> secureEntries = getVault().read();
    assertEquals(1, secureEntries.size());
    assertEquals("key1", secureEntries.iterator().next().getKey());
  }

  @Test
  public void test_6_delete() throws VaultOperationException {
    // delete entry
    final Optional<SecureEntry> secureEntryOptional = getVault().delete("key1");
    assertTrue(secureEntryOptional.isPresent());
    // check that the vault is really empty
    assertTrue(getVault().read().isEmpty());
    assertFalse(getVault().read("key1").isPresent());
  }

  @Test
  public void test_7_writeTwo() throws VaultOperationException {
    // write
    final SecureEntry secureEntry1 = getVault().write(UnsecureEntry.of("key1", "dummy1"));
    final SecureEntry secureEntry2 = getVault().write(UnsecureEntry.of("key2", "dummy2"));
    assertNotNull(secureEntry1);
    assertNotNull(secureEntry2);
    assertEquals(2, getVault().read().size());
    assertEquals(secureEntry1, getVault().read(secureEntry1.getKey()).get());
    assertEquals(secureEntry2, getVault().read(secureEntry2.getKey()).get());
  }
}

