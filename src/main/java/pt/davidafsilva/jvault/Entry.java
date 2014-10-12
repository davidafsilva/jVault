package pt.davidafsilva.jvault;

/**
 * This interface represents a key-value pair entry.
 *
 * @author David Silva
 */
public interface Entry {

  /**
   * Returns the key associated with this entry
   *
   * @return the key
   */
  String getKey();

  /**
   * Returns the value associated with this entry
   *
   * @return the value
   */
  String getValue();

  /**
   * Returns the creation date of the entry
   *
   * @return the entry's creation date
   */
  long getCreationDate();
}
