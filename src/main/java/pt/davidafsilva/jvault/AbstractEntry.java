package pt.davidafsilva.jvault;

import java.util.Objects;

/**
 * This entry contains the common code that both {@link UnsecureEntry unsecure} and {@link
 * SecureEntry secure} entries share.
 *
 * @author David Silva
 */
class AbstractEntry implements Entry {

  // properties
  private final long timestamp;
  private final String key;
  private final String value;

  /**
   * Default constructor of the entry
   *
   * @param timestamp the entry's creation timestamp
   * @param key       the entry key
   * @param value     the entry value
   */
  AbstractEntry(final long timestamp, final String key, final String value) {
    Objects.requireNonNull(key, "key must not be null");
    Objects.requireNonNull(value, "value must not be null");
    this.timestamp = timestamp;
    this.key = key;
    this.value = value;
  }

  @Override
  public long getCreationDate() {
    return timestamp;
  }

  @Override
  public String getKey() {
    return key;
  }

  @Override
  public String getValue() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }

    final AbstractEntry that = (AbstractEntry) o;
    if (!key.equals(that.key)) {
      return false;
    }
    return value.equals(that.value);

  }

  @Override
  public int hashCode() {
    int result = key.hashCode();
    result = 31 * result + value.hashCode();
    return result;
  }
}
