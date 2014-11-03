package pt.davidafsilva.jvault.vault;

import java.nio.file.Path;

/**
 * Unit test for the byte file based implementation of the vault
 *
 * @author David Silva
 */
public class ByteFileVaultTest extends FileVaultTest {

  @Override
  FileVault createVault(final Path path) throws VaultInitializationException {
    return new ByteFileVault("12345678901234567890123456789012", "12345678", 1024, 128, path);
  }
}
