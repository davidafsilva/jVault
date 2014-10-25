package pt.davidafsilva.jvault.vault;

/**
 * This exception denotes a corrupted file vault. Typically with an invalid MAC or incorrectly
 * written data.
 *
 * @author David Silva
 */
public final class VaultCorruptedException extends RuntimeException {

  /**
   * Constructs the corruption exception with the error message.
   *
   * @param message the brief error description
   */
  VaultCorruptedException(final String message) {
    super(message);
  }
}
