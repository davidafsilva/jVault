package pt.davidafsilva.jvault;

import java.util.Collection;
import java.util.Optional;

/**
 * The secure vault definition.
 *
 * @author David Silva
 */
public interface Vault {

  /**
   * Reads all of the stored entries from the vault.
   *
   * @return the stored entries, an empty collection is returned when nothing is stored.
   * @see #read(String)
   */
  Collection<SecureEntry> read();

  /**
   * Reads the entry stored in the vault with the given {@code key}.
   *
   * @param key the key for the entry
   * @return the entry associated with the given {@code key}, or none if there's no such mapping.
   * @see #read()
   * @see Optional
   */
  Optional<SecureEntry> read(final String key);

  /**
   * Writes the given key-value pair to the vault
   *
   * @param entry the unsecure entry
   * @return the secure entry for the given key-value pair
   * @throws VaultOperationException if an error occurs while ciphering the entry
   */
  SecureEntry write(final UnsecureEntry entry) throws VaultOperationException;

  /**
   * Deletes the entry stored in the vault with the given {@code key}.
   *
   * @param key the key for the entry
   * @return the deleted entry, or none if there's no such mapping.
   * @see Optional
   */
  Optional<SecureEntry> delete(final String key);

  /**
   * Translate the secured entry and returns the original (unsecured) entry
   *
   * @param entry the entry to be translated
   * @return the original value
   * @throws IllegalArgumentException if the given entry is not in the vault
   * @throws VaultOperationException  if an error occurs while deciphering the entry
   * @see #write(UnsecureEntry)
   */
  UnsecureEntry translate(final SecureEntry entry) throws VaultOperationException;
}
