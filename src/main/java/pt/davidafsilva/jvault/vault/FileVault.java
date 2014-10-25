package pt.davidafsilva.jvault.vault;

import java.io.IOException;

/**
 * The secure file based vault definition.
 *
 * @author David Silva
 */
public interface FileVault extends Vault {

  /**
   * Persists the changes made (if any) to the vault file.
   *
   * The file can only be written once at a time, so concurrent calls are either ignored or queued
   * for later execution. Implementations should specify it's behavior.
   *
   * @throws IOException             if an I/O error occurs while writing the vault
   * @throws VaultOperationException if the any of the security settings are not supported or an
   *                                 invalid key is used.
   */
  void persist() throws IOException, VaultOperationException;
}
