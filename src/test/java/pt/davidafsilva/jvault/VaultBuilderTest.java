package pt.davidafsilva.jvault;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;

/**
 * Unit test for the vaults builder implementation
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

  @Test
  public void test_success() throws VaultInitializationException {
    final Vault vault = VaultBuilder.create().password("abc").salt("123").build();
    assertNotNull(vault);
  }
}
