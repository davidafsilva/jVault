package pt.davidafsilva.jvault;

/**
 * This exception denotes an error that occurred while an arbitrary vault was being initialized,
 * such as invalid password and/or salts were provided, or the JVM not supporting the used
 * algorithm.
 *
 * @author David Silva
 */
public final class VaultInitializationException extends Exception {

  /**
   * Constructs the initialization exception with the error message and original cause.
   *
   * @param message the brief error description
   * @param cause   the original cause of the exception
   */
  VaultInitializationException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
