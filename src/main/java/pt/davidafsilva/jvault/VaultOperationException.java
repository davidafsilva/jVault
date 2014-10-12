package pt.davidafsilva.jvault;

/**
 * This exception denotes an error that occurred while the vault was executing some operation, such
 * as ciphering or deciphering entry data.
 *
 * @author David Silva
 */
public class VaultOperationException extends Exception {

  /**
   * Constructs the operational exception with the error message and original cause.
   *
   * @param message the brief error description
   * @param cause   the original cause of the exception
   */
  VaultOperationException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
