package pt.davidafsilva.jvault.vault;

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
}
