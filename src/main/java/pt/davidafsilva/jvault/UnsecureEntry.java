package pt.davidafsilva.jvault;

import java.time.Instant;

/**
 * This entity represents an unsecured {@link Entry}, in which the {@link #getValue() value} is in
 * plaintext.
 *
 * @author David Silva
 * @see SecureEntry
 */
public final class UnsecureEntry extends AbstractEntry {

  /**
   * Creates a new secured entry
   *
   * @param timestamp the entry's creation timestamp
   * @param key       the original key
   * @param value     the plaintext value
   */
  private UnsecureEntry(final long timestamp, final String key, final String value) {
    super(timestamp, key, value);
  }

  /**
   * Static factory method for the creation of an {@link UnsecureEntry}.
   *
   * @param key   the original key
   * @param value the plaintext value
   * @return an unsecure entry with the given key-value pair
   */
  public static UnsecureEntry of(final String key, final String value) {
    return new UnsecureEntry(Instant.now().toEpochMilli(), key, value);
  }
}
