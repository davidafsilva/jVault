package pt.davidafsilva.jvault;

import java.time.Instant;

/**
 * This entity represents a secured {@link Entry}, in which the {@link #getValue() value} is
 * cryptographically secured by a {@link Vault}.
 *
 * @author David Silva
 */
public final class SecureEntry extends AbstractEntry {

  /**
   * Creates a new secured entry
   *
   * @param timestamp the entry's creation timestamp
   * @param key       the original key
   * @param value     the secure value
   */
  SecureEntry(final long timestamp, final String key, final String value) {
    super(timestamp, key, value);
  }

  /**
   * Static factory method for the creation of an {@link SecureEntry}.
   *
   * @param key   the original key
   * @param value the ciphered value
   * @return an secure entry with the given key-value pair
   */
  public static SecureEntry of(final String key, final String value) {
    return new SecureEntry(Instant.now().toEpochMilli(), key, value);
  }
}
