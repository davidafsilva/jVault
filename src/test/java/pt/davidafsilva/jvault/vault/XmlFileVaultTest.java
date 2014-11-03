package pt.davidafsilva.jvault.vault;

import org.junit.FixMethodOrder;
import org.junit.runners.MethodSorters;

import java.nio.file.Path;

/**
 * Unit test for the XML file based implementation of the vault
 *
 * @author David Silva
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class XmlFileVaultTest extends FileVaultTest {

  @Override
  FileVault createVault(final Path path) throws VaultInitializationException {
    return new XmlFileVault("12345678901234567890123456789012", "12345678", 1024, 128, path);
  }
}
